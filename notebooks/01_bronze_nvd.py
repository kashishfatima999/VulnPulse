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
# MAGIC
# MAGIC **Where this differs from `02_bronze_kev`:** KEV has no `load_type` widget (always FULL), no
# MAGIC window, no watermark table, and reads one file instead of `page_*.json`. Everything else
# MAGIC (manifest, batch id, verbatim append, audit row, landing purge) is the same pattern.

# COMMAND ----------

# MAGIC %load_ext autoreload
# MAGIC %autoreload 2

# COMMAND ----------

import os
import sys

# Notebook lives in notebooks/, code in src/. Put src on the path so `import vulnpulse` works and
# the notebook runs the exact code that the unit tests and CI test.
SRC_PATH = os.path.abspath(os.path.join(os.getcwd(), "..", "src"))
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

# noqa: E402 = "import not at top of file". Deliberate: the sys.path lines above must run first.
from datetime import timedelta  # noqa: E402

from vulnpulse.audit import execution_log as log  # noqa: E402   audit table helpers
from vulnpulse.bronze import nvd as bronze_nvd  # noqa: E402     read / explode / to_bronze / append
from vulnpulse.ingestion.landing import parse_utc, read_manifest  # noqa: E402
from vulnpulse.utils import watermark as wm  # noqa: E402        NVD-only: KEV imports no watermark
from vulnpulse.utils.params import BronzeRunParams, utc_now  # noqa: E402

# All timestamps in this pipeline are UTC. Setting the session zone stops Spark from converting
# naive timestamps to the cluster's local time.
spark.conf.set("spark.sql.session.timeZone", "UTC")

# COMMAND ----------

# Default source for a quick FULL demo: the Phase 1 sample file committed in data/ (10 CVEs).
DEFAULT_SAMPLE = "file:" + os.path.abspath(
    os.path.join(os.getcwd(), "..", "data", "nvd_full_load_sample.json")
)

# Widgets = run parameters. The Job passes them as base_parameters; a human sets them in the UI.
# load_type is the NVD-only widget: KEV's notebook has no such choice.
dbutils.widgets.dropdown("load_type", "FULL", ["FULL", "INCREMENTAL", "BACKFILL"])
dbutils.widgets.text("source_path", DEFAULT_SAMPLE)
dbutils.widgets.text("start_date", "")  # fallback only; normally blank (manifest decides)
dbutils.widgets.text("end_date", "")  # fallback only; normally blank
dbutils.widgets.text("batch_id", "")  # normally blank (manifest id is used)
dbutils.widgets.text("catalog", "workspace")

load_type = dbutils.widgets.get("load_type")
source_path = dbutils.widgets.get("source_path").strip().rstrip("/") or None
# The manifest written by fetch_nvd.py is the source of truth for the window and batch id.
# FULL loads come from a yearly feed file, not the fetch script, so they have no manifest.
manifest = read_manifest(source_path) if (source_path and load_type != "FULL") else None

# BronzeRunParams validates the combination (e.g. a load type that needs a window) and derives
# the schema names (vulnpulse_bronze / vulnpulse_gold) from the catalog.
params = BronzeRunParams(
    load_type=load_type,
    catalog=dbutils.widgets.get("catalog").strip(),
    source_path=source_path,
    start_date=dbutils.widgets.get("start_date").strip() or None,
    end_date=dbutils.widgets.get("end_date").strip() or None,
    # Prefer the batch id the fetch script minted, so landing folder and Bronze rows share it.
    batch_id=dbutils.widgets.get("batch_id").strip() or (manifest or {}).get("batch_id", ""),
)

# Three tables this notebook touches. Log and watermark live in the Gold schema (shared control
# tables for all layers); the data table lives in Bronze.
BRONZE_TABLE = f"{params.bronze_schema}.{bronze_nvd.BRONZE_NVD_TABLE}"
LOG_TABLE = f"{params.gold_schema}.{log.EXECUTION_LOG_TABLE}"
WATERMARK_TABLE = f"{params.gold_schema}.{wm.WATERMARK_TABLE}"  # NVD-only

print("parameters:", params.as_dict())
print("manifest:  ", manifest or "none")
print("bronze table:   ", BRONZE_TABLE)
print("log table:      ", LOG_TABLE)
print("watermark table:", WATERMARK_TABLE)

# COMMAND ----------

# Idempotent DDL: CREATE TABLE IF NOT EXISTS for all three. Safe on every run, first or hundredth.
bronze_nvd.ensure_table(spark, BRONZE_TABLE)
log.ensure_table(spark, LOG_TABLE)
wm.ensure_table(spark, WATERMARK_TABLE)  # NVD-only: KEV creates no watermark table

# COMMAND ----------

# The load. Structure: try (do the work) / except (record failure, re-raise so the Job task goes
# red) / finally (ALWAYS write the audit row, success or failure). This is why every run, even a
# crashed one, appears in pipeline_execution_logs.
started_at = utc_now()
rows_read = rows_written = 0
error = None
window = None
source = params.source_path

try:
    # ---- 1. Read the landed files ---------------------------------------------------------
    if params.load_type == "FULL":
        # One feed file (e.g. nvdcve-2.0-2020.json.gz). No window, no manifest, no watermark.
        pages = bronze_nvd.read_nvd_pages(spark, params.source_path)
    else:
        # INCREMENTAL or BACKFILL: a landing folder of page_*.json produced by fetch_nvd.py.
        # Work out the window this folder covers, in priority order:
        if manifest:
            # (a) from the manifest: this is the normal path, used by every run so far
            window = (parse_utc(manifest["window_start"]), parse_utc(manifest["window_end"]))
            source = manifest.get("source_uri", params.source_path)
            if manifest.get("load_type") != params.load_type:
                print(
                    f"WARNING: manifest says {manifest.get('load_type')} but widget says "
                    f"{params.load_type}; the widget wins for watermark behaviour."
                )
        elif params.start_date and params.end_date:
            # (b) from the two widgets: fallback for a folder uploaded without a manifest
            window = (parse_utc(params.start_date), parse_utc(params.end_date))
        else:
            # (c) neither: refuse. An incremental/backfill without a known window would make
            # the watermark and the audit row meaningless.
            raise ValueError(
                f"{params.load_type} needs a landing folder containing manifest.json "
                "(run scripts/fetch_nvd.py), or explicit start_date and end_date."
            )
        print(f"window: {window[0].isoformat()} -> {window[1].isoformat()}")

        if params.load_type == "INCREMENTAL":
            # NVD-only gap check. If the window starts AFTER the stored watermark there is a
            # hole: records modified in between were never fetched. We warn, not fail, and the
            # fix is a BACKFILL of exactly that gap.
            current_wm = wm.read_watermark(spark, WATERMARK_TABLE, wm.SOURCE_NVD)
            print("watermark before run:", current_wm)
            if current_wm and window[0] > current_wm:
                print(
                    f"WARNING: gap of {window[0] - current_wm} between the watermark and this "
                    "window's start. Records modified in that gap are not in this batch."
                )

        if (manifest or {}).get("records", 1) == 0:
            # Empty window (NVD had nothing modified). No page files exist, so build an empty
            # DataFrame with the right schema instead of reading a glob that matches nothing.
            pages = spark.createDataFrame([], bronze_nvd.NVD_PAGE_RAW_SCHEMA)
        else:
            # Many page files, read as one DataFrame. KEV reads one file here instead.
            pages = bronze_nvd.read_nvd_pages(spark, f"{params.source_path}/page_*.json")

    # ---- 2. Shape and append ---------------------------------------------------------------
    raw = bronze_nvd.explode_cves(pages)  # 1 row per page -> 1 row per CVE (raw_json)
    rows_read = raw.count()
    bronze_df = bronze_nvd.to_bronze(  # lift cve_id + lastModified, add hash + provenance
        raw,
        source_uri=source,
        load_type=params.load_type,
        batch_id=params.batch_id,
        load_timestamp=started_at,
    )
    bronze_nvd.append(bronze_df, BRONZE_TABLE)  # append-only; never update or delete
    # Count what actually landed in the table for this batch (not what we intended to write).
    rows_written = spark.table(BRONZE_TABLE).where(f"batch_id = '{params.batch_id}'").count()

    # ---- 3. Advance the watermark (INCREMENTAL only) ---------------------------------------
    # This block is the single biggest difference from KEV and from BACKFILL.
    #   INCREMENTAL: bookmark moves forward to the newest lastModified we have now seen.
    #   BACKFILL:    skipped. A past window says nothing about "everything up to now", so moving
    #                the bookmark would either re-load or skip data. The rows still go to Bronze.
    #   FULL:        skipped. A feed file is a snapshot, not a window.
    #   KEV:         no watermark at all; every run is a full snapshot.
    if params.load_type == "INCREMENTAL":
        # Advance only after a successful append. Zero rows -> the window end is proven empty.
        max_modified = (
            spark.table(BRONZE_TABLE)
            .where(f"batch_id = '{params.batch_id}'")
            .agg({"source_last_modified": "max"})
            .first()[0]
        )
        # New bookmark = newest source stamp in this batch, or the window end if the batch was
        # empty (NVD told us nothing changed up to window end, so that is proven covered).
        new_wm = parse_utc(max_modified) if max_modified else window[1]
        wm.write_watermark(spark, WATERMARK_TABLE, wm.SOURCE_NVD, new_wm, params.batch_id)
        # The 10-minute overlap: NVD can publish a record a few minutes after the time stamped
        # on it. Starting the next fetch 10 min before the bookmark catches those late records.
        # The duplicates this brings are harmless (Bronze append-only, Silver MERGE no-ops).
        next_start = (new_wm - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%S")
        print("watermark after run: ", new_wm)
        print(f"next fetch:           python scripts/fetch_nvd.py --start {next_start}")

    # ---- 4. Purge the landing folder -------------------------------------------------------
    # Once the rows are in Bronze (which is itself the durable raw copy) the landing files are
    # redundant. Deleting them keeps volume storage near zero. Only volume paths are purged;
    # a FULL load from a feed file or the sample is left alone.
    if params.load_type != "FULL" and params.source_path.startswith("/Volumes/"):
        dbutils.fs.rm(params.source_path, True)  # FinOps: landing files are purged once in Bronze

    status = log.STATUS_SUCCESS
except Exception as exc:  # noqa: BLE001 - logged then re-raised
    # Catch everything so the failure is recorded, then re-raise so the notebook/Job task fails.
    status = log.STATUS_FAILURE
    error = f"{type(exc).__name__}: {exc}"[:2000]
    raise
finally:
    # ---- 5. Audit row, written on every path ----------------------------------------------
    # One Raw-to-Bronze row per run: who (batch_id), what (source + window), how (load_type and
    # the full parameters including a copy of the manifest, so it survives the purge above),
    # when (started/finished), outcome (status, counts, error text).
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
            rows_updated=0,  # Bronze never updates
            error_message=error,
        ),
        LOG_TABLE,
    )

print(f"{status}: read {rows_read}, wrote {rows_written} rows to {BRONZE_TABLE}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Results

# COMMAND ----------

# The audit row this run just wrote.
display(
    spark.table(LOG_TABLE)
    .where(f"batch_id = '{params.batch_id}'")
    .select("layer", "load_type", "source", "status", "rows_read", "rows_inserted", "started_at")
)

# COMMAND ----------

# A sample of the rows this run wrote, newest source stamp first.
display(
    spark.table(BRONZE_TABLE)
    .where(f"batch_id = '{params.batch_id}'")
    .select("cve_id", "source_last_modified", "payload_sha256", "load_type", "load_timestamp")
    .orderBy("source_last_modified", ascending=False)
    .limit(20)
)

# COMMAND ----------

# Load history: one line per batch, in load order. FULL / INCREMENTAL / BACKFILL are all visible.
display(
    spark.sql(
        f"SELECT batch_id, load_type, count(*) AS rows, min(load_timestamp) AS loaded_at "
        f"FROM {BRONZE_TABLE} GROUP BY batch_id, load_type ORDER BY loaded_at"
    )
)

# COMMAND ----------

# Watermark history (NVD-only). Each INCREMENTAL run adds a row; BACKFILL and FULL add none.
display(spark.table(WATERMARK_TABLE).orderBy("load_timestamp", ascending=False))
