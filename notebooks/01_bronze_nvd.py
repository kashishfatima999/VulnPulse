# Databricks notebook source
# /// script
# [tool.databricks.environment]
# environment_version = "6"
# ///
# MAGIC %md
# MAGIC # 01 · Raw-to-Bronze: NVD
# MAGIC
# MAGIC Thin runner. Reads parameters, calls `vulnpulse` functions, writes one audit row, shows results.
# MAGIC
# MAGIC Databricks Free Edition serverless has **no outbound internet**, so acquisition happens on a
# MAGIC laptop with `scripts/fetch_nvd.py`, which writes `page_*.json` + `manifest.json`. That folder is
# MAGIC uploaded to the landing volume and named here as `source_path`. This notebook never calls the
# MAGIC network.
# MAGIC
# MAGIC | Widget | FULL | INCREMENTAL | BACKFILL |
# MAGIC |---|---|---|---|
# MAGIC | `load_type` | `FULL` | `INCREMENTAL` | `BACKFILL` |
# MAGIC | `source_path` | feed file or folder (plain or .gz) | landing folder with manifest | landing folder with manifest |
# MAGIC | `start_date` / `end_date` | ignored | ignored (manifest decides) | optional override when the folder has no manifest |
# MAGIC | `batch_id` | blank = auto | blank = auto (manifest id is preferred) | same |
# MAGIC | `catalog` | Unity Catalog catalog, default `workspace` | | |
# MAGIC
# MAGIC **INCREMENTAL** appends the landed pages and then advances the watermark to the largest
# MAGIC `lastModified` seen. **BACKFILL** appends and leaves the watermark alone.

# COMMAND ----------

import os
import sys

SRC_PATH = os.path.abspath(os.path.join(os.getcwd(), "..", "src"))
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

from datetime import timedelta  # noqa: E402

from vulnpulse.audit import execution_log as log  # noqa: E402
from vulnpulse.bronze import nvd as bronze_nvd  # noqa: E402
from vulnpulse.ingestion.landing import parse_utc, read_manifest  # noqa: E402
from vulnpulse.utils import watermark as wm  # noqa: E402
from vulnpulse.utils.params import BronzeRunParams, utc_now  # noqa: E402

spark.conf.set("spark.sql.session.timeZone", "UTC")

# COMMAND ----------

DEFAULT_SAMPLE = "file:" + os.path.abspath(
    os.path.join(os.getcwd(), "..", "data", "nvd_full_load_sample.json")
)

dbutils.widgets.dropdown("load_type", "FULL", ["FULL", "INCREMENTAL", "BACKFILL"])
dbutils.widgets.text("source_path", DEFAULT_SAMPLE)
dbutils.widgets.text("start_date", "")
dbutils.widgets.text("end_date", "")
dbutils.widgets.text("batch_id", "")
dbutils.widgets.text("catalog", "workspace")

load_type = dbutils.widgets.get("load_type")
source_path = dbutils.widgets.get("source_path").strip().rstrip("/") or None
manifest = read_manifest(source_path) if (source_path and load_type != "FULL") else None

params = BronzeRunParams(
    load_type=load_type,
    catalog=dbutils.widgets.get("catalog").strip(),
    source_path=source_path,
    start_date=dbutils.widgets.get("start_date").strip() or None,
    end_date=dbutils.widgets.get("end_date").strip() or None,
    # Prefer the batch id the fetch script minted, so landing folder and Bronze rows share it.
    batch_id=dbutils.widgets.get("batch_id").strip() or (manifest or {}).get("batch_id", ""),
)

BRONZE_TABLE = f"{params.bronze_schema}.{bronze_nvd.BRONZE_NVD_TABLE}"
LOG_TABLE = f"{params.gold_schema}.{log.EXECUTION_LOG_TABLE}"
WATERMARK_TABLE = f"{params.gold_schema}.{wm.WATERMARK_TABLE}"

print("parameters:", params.as_dict())
print("manifest:  ", manifest or "none")
print("bronze table:   ", BRONZE_TABLE)
print("log table:      ", LOG_TABLE)
print("watermark table:", WATERMARK_TABLE)

# COMMAND ----------

bronze_nvd.ensure_table(spark, BRONZE_TABLE)
log.ensure_table(spark, LOG_TABLE)
wm.ensure_table(spark, WATERMARK_TABLE)

# COMMAND ----------

started_at = utc_now()
rows_read = rows_written = 0
error = None
window = None
source = params.source_path

try:
    if params.load_type == "FULL":
        pages = bronze_nvd.read_nvd_pages(spark, params.source_path)
    else:
        if manifest:
            window = (parse_utc(manifest["window_start"]), parse_utc(manifest["window_end"]))
            source = manifest.get("source_uri", params.source_path)
            if manifest.get("load_type") != params.load_type:
                print(
                    f"WARNING: manifest says {manifest.get('load_type')} but widget says "
                    f"{params.load_type}; the widget wins for watermark behaviour."
                )
        elif params.start_date and params.end_date:
            window = (parse_utc(params.start_date), parse_utc(params.end_date))
        else:
            raise ValueError(
                f"{params.load_type} needs a landing folder containing manifest.json "
                "(run scripts/fetch_nvd.py), or explicit start_date and end_date."
            )
        print(f"window: {window[0].isoformat()} -> {window[1].isoformat()}")

        if params.load_type == "INCREMENTAL":
            current_wm = wm.read_watermark(spark, WATERMARK_TABLE, wm.SOURCE_NVD)
            print("watermark before run:", current_wm)
            if current_wm and window[0] > current_wm:
                print(
                    f"WARNING: gap of {window[0] - current_wm} between the watermark and this "
                    "window's start. Records modified in that gap are not in this batch."
                )

        if (manifest or {}).get("records", 1) == 0:
            pages = spark.createDataFrame([], bronze_nvd.NVD_PAGE_RAW_SCHEMA)
        else:
            pages = bronze_nvd.read_nvd_pages(spark, f"{params.source_path}/page_*.json")

    raw = bronze_nvd.explode_cves(pages)
    rows_read = raw.count()
    bronze_df = bronze_nvd.to_bronze(
        raw,
        source_uri=source,
        load_type=params.load_type,
        batch_id=params.batch_id,
        load_timestamp=started_at,
    )
    bronze_nvd.append(bronze_df, BRONZE_TABLE)
    rows_written = spark.table(BRONZE_TABLE).where(f"batch_id = '{params.batch_id}'").count()

    if params.load_type == "INCREMENTAL":
        # Advance only after a successful append. Zero rows -> the window end is proven empty.
        max_modified = (
            spark.table(BRONZE_TABLE)
            .where(f"batch_id = '{params.batch_id}'")
            .agg({"source_last_modified": "max"})
            .first()[0]
        )
        new_wm = parse_utc(max_modified) if max_modified else window[1]
        wm.write_watermark(spark, WATERMARK_TABLE, wm.SOURCE_NVD, new_wm, params.batch_id)
        next_start = (new_wm - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S")
        print("watermark after run: ", new_wm)
        print(f"next fetch:           python scripts/fetch_nvd.py --start {next_start}")

    if params.load_type != "FULL" and params.source_path.startswith("/Volumes/"):
        dbutils.fs.rm(params.source_path, True)  # FinOps: landing files are purged once in Bronze

    status = log.STATUS_SUCCESS
except Exception as exc:  # noqa: BLE001 - logged then re-raised
    status = log.STATUS_FAILURE
    error = f"{type(exc).__name__}: {exc}"[:2000]
    raise
finally:
    log.append(
        log.build_log_row(
            spark,
            batch_id=params.batch_id,
            layer=log.LAYER_RAW_TO_BRONZE,
            source=(
                f"{source} [{window[0].isoformat()}..{window[1].isoformat()}]" if window else source
            ),
            load_type=params.load_type,
            parameters={**params.as_dict(), "manifest": manifest},
            started_at=started_at,
            finished_at=utc_now(),
            status=status,
            rows_read=rows_read,
            rows_inserted=rows_written,
            rows_updated=0,
            error_message=error,
        ),
        LOG_TABLE,
    )

print(f"{status}: read {rows_read}, wrote {rows_written} rows to {BRONZE_TABLE}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Results

# COMMAND ----------

display(
    spark.table(LOG_TABLE)
    .where(f"batch_id = '{params.batch_id}'")
    .select("layer", "load_type", "source", "status", "rows_read", "rows_inserted", "started_at")
)

# COMMAND ----------

display(
    spark.table(BRONZE_TABLE)
    .where(f"batch_id = '{params.batch_id}'")
    .select("cve_id", "source_last_modified", "payload_sha256", "load_type", "load_timestamp")
    .orderBy("source_last_modified", ascending=False)
    .limit(20)
)

# COMMAND ----------

display(
    spark.sql(
        f"SELECT batch_id, load_type, count(*) AS rows, min(load_timestamp) AS loaded_at "
        f"FROM {BRONZE_TABLE} GROUP BY batch_id, load_type ORDER BY loaded_at"
    )
)

# COMMAND ----------

display(spark.table(WATERMARK_TABLE).orderBy("load_timestamp", ascending=False))
