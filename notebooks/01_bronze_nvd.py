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
# MAGIC | Widget | FULL | INCREMENTAL | BACKFILL |
# MAGIC |---|---|---|---|
# MAGIC | `load_type` | `FULL` | `INCREMENTAL` | `BACKFILL` |
# MAGIC | `source_path` | file or folder of NVD JSON (plain or .gz) | ignored | ignored |
# MAGIC | `start_date` | ignored | optional seed for the very first run (no watermark yet) | required, ISO-8601 UTC |
# MAGIC | `end_date` | ignored | ignored (now) | required, ISO-8601 UTC |
# MAGIC | `batch_id` | blank = auto | blank = auto | blank = auto |
# MAGIC | `catalog` | Unity Catalog catalog, default `workspace` | | |
# MAGIC | `api_key_scope` / `api_key_name` | ignored | optional Databricks secret holding an NVD API key | same |
# MAGIC
# MAGIC **INCREMENTAL** asks the NVD API for everything modified since the stored watermark minus a
# MAGIC 10-minute overlap, lands the pages in the volume, appends them to Bronze, then advances the
# MAGIC watermark. **BACKFILL** does the same for an explicit window and leaves the watermark alone.

# COMMAND ----------

import os
import sys
from datetime import datetime, timezone

SRC_PATH = os.path.abspath(os.path.join(os.getcwd(), "..", "src"))
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

from vulnpulse.audit import execution_log as log  # noqa: E402
from vulnpulse.bronze import nvd as bronze_nvd  # noqa: E402
from vulnpulse.ingestion import nvd_api  # noqa: E402
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
dbutils.widgets.text("api_key_scope", "")
dbutils.widgets.text("api_key_name", "")

params = BronzeRunParams(
    load_type=dbutils.widgets.get("load_type"),
    catalog=dbutils.widgets.get("catalog").strip(),
    source_path=dbutils.widgets.get("source_path").strip() or None,
    start_date=dbutils.widgets.get("start_date").strip() or None,
    end_date=dbutils.widgets.get("end_date").strip() or None,
    batch_id=dbutils.widgets.get("batch_id"),
)

BRONZE_TABLE = f"{params.bronze_schema}.{bronze_nvd.BRONZE_NVD_TABLE}"
LOG_TABLE = f"{params.gold_schema}.{log.EXECUTION_LOG_TABLE}"
WATERMARK_TABLE = f"{params.gold_schema}.{wm.WATERMARK_TABLE}"
LANDING_DIR = f"/Volumes/{params.catalog}/vulnpulse_bronze/landing/nvd/{params.batch_id}"

api_key = None
scope, name = dbutils.widgets.get("api_key_scope").strip(), dbutils.widgets.get("api_key_name").strip()
if scope and name:
    api_key = dbutils.secrets.get(scope, name)

print("parameters:", params.as_dict())
print("bronze table:   ", BRONZE_TABLE)
print("log table:      ", LOG_TABLE)
print("watermark table:", WATERMARK_TABLE)
print("api key:        ", "from secret" if api_key else "none (public rate limit)")

# COMMAND ----------

bronze_nvd.ensure_table(spark, BRONZE_TABLE)
log.ensure_table(spark, LOG_TABLE)
wm.ensure_table(spark, WATERMARK_TABLE)


def parse_utc(value):
    """Widget text -> aware UTC datetime. Accepts '2026-10-01', '2026-10-01T00:00:00', trailing 'Z'."""
    if value is None:
        return None
    ts = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)


# COMMAND ----------

started_at = utc_now()
rows_read = rows_written = 0
error = None
window = None
fetch = None

try:
    if params.load_type == "FULL":
        source = params.source_path
        pages = bronze_nvd.read_nvd_pages(spark, source)
    else:
        if params.load_type == "INCREMENTAL":
            current_wm = wm.read_watermark(spark, WATERMARK_TABLE, wm.SOURCE_NVD)
            window = wm.incremental_window(
                current_wm, started_at, seed_start=parse_utc(params.start_date)
            )
            print("watermark before run:", current_wm)
        else:  # BACKFILL
            window = (parse_utc(params.start_date), parse_utc(params.end_date))
        print(f"API window: {window[0].isoformat()} -> {window[1].isoformat()}")

        fetch = nvd_api.fetch_window_to_files(window[0], window[1], LANDING_DIR, api_key=api_key)
        print(
            f"fetched {fetch.records} records in {fetch.pages} page(s), "
            f"{fetch.requests} request(s), totalResults={fetch.total_results}"
        )
        source = nvd_api.build_page_url(window[0], window[1], 0)
        pages = (
            bronze_nvd.read_nvd_pages(spark, LANDING_DIR)
            if fetch.pages
            else spark.createDataFrame([], bronze_nvd.NVD_PAGE_RAW_SCHEMA)
        )

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
        print("watermark after run: ", new_wm)

    if fetch is not None and fetch.pages:
        dbutils.fs.rm(LANDING_DIR, True)  # FinOps: landing files are purged once in Bronze

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
                params.source_path
                if params.load_type == "FULL"
                else f"nvd-api {window[0].isoformat()}..{window[1].isoformat()}"
                if window
                else "nvd-api (window not computed)"
            ),
            load_type=params.load_type,
            parameters=params.as_dict(),
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
