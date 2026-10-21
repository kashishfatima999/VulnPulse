# Databricks notebook source
# /// script
# [tool.databricks.environment]
# environment_version = "6"
# ///
# MAGIC %md
# MAGIC # 02 · Raw-to-Bronze: CISA KEV
# MAGIC
# MAGIC The KEV catalog has no incremental API, so every run is a FULL snapshot. Free Edition serverless
# MAGIC cannot reach the internet, so the catalog is downloaded on a laptop with `scripts/fetch_kev.py`
# MAGIC and uploaded to the landing volume; `source_path` names that folder (or a single JSON file).
# MAGIC
# MAGIC | Widget | Meaning |
# MAGIC |---|---|
# MAGIC | `source_path` | landing folder containing `known_exploited_vulnerabilities.json` (+ `manifest.json`), or a JSON file |
# MAGIC | `batch_id` | blank = manifest id if present, else auto |
# MAGIC | `catalog` | Unity Catalog catalog, default `workspace` |
# MAGIC
# MAGIC **Where this differs from `01_bronze_nvd`:** no `load_type`, `start_date` or `end_date` widgets
# MAGIC (always FULL, no window), no watermark table, no gap check, no "next fetch" hint, and one file
# MAGIC is read instead of `page_*.json`. Everything else (manifest, batch id, verbatim append, audit
# MAGIC row, landing purge) is the same pattern, which is why the two notebooks look alike.

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
# Compare 01_bronze_nvd: no `watermark` import and no `timedelta` here, because KEV has no bookmark.
from vulnpulse.audit import execution_log as log  # noqa: E402   audit table helpers
from vulnpulse.bronze import kev as bronze_kev  # noqa: E402     read / explode / to_bronze / append
from vulnpulse.ingestion.landing import read_manifest  # noqa: E402
from vulnpulse.utils.params import new_batch_id, utc_now  # noqa: E402

# All timestamps in this pipeline are UTC.
spark.conf.set("spark.sql.session.timeZone", "UTC")

# COMMAND ----------


# Widgets = run parameters. Only three, versus six in the NVD notebook: there is no load_type
# (always FULL) and no window dates (the catalog is not time-sliced).
dbutils.widgets.text("source_path", "")
dbutils.widgets.text("batch_id", "")  # normally blank (manifest id is used)
dbutils.widgets.text("catalog", "workspace")

CATALOG = dbutils.widgets.get("catalog").strip() or "workspace"
SOURCE_PATH = dbutils.widgets.get("source_path").strip().rstrip("/")

# source_path may be a landing folder (normal: fetch_kev.py output with manifest.json) or a single
# JSON file (e.g. the Phase 1 sample in data/). A folder has a manifest; a bare file does not.
is_folder = not SOURCE_PATH.lower().endswith(".json")
manifest = read_manifest(SOURCE_PATH) if (SOURCE_PATH and is_folder) else None
# Batch id priority: widget > manifest (minted by fetch_kev.py) > new. Same rule as NVD.
BATCH_ID = dbutils.widgets.get("batch_id").strip() or (manifest or {}).get("batch_id") or new_batch_id()
# One file to read. NVD reads a glob of page_*.json instead.
READ_PATH = f"{SOURCE_PATH}/known_exploited_vulnerabilities.json" if is_folder else SOURCE_PATH
# Provenance: the CISA URL from the manifest when we have one, else the path we were given.
SOURCE_URI = (manifest or {}).get("source_uri", SOURCE_PATH)

# Two tables, not three: no watermark table for KEV.
BRONZE_TABLE = f"{CATALOG}.vulnpulse_bronze.{bronze_kev.BRONZE_KEV_TABLE}"
LOG_TABLE = f"{CATALOG}.vulnpulse_gold.{log.EXECUTION_LOG_TABLE}"

print("batch_id:    ", BATCH_ID)
print("read path:   ", READ_PATH)
print("source uri:  ", SOURCE_URI)
print("manifest:    ", manifest or "none")
print("bronze table:", BRONZE_TABLE)


# COMMAND ----------

# Idempotent DDL: CREATE TABLE IF NOT EXISTS. Safe on every run.
bronze_kev.ensure_table(spark, BRONZE_TABLE)
log.ensure_table(spark, LOG_TABLE)

# COMMAND ----------

# The load. Same try / except / finally shape as NVD: the audit row is ALWAYS written.
started_at = utc_now()
rows_read = rows_written = 0
error = None

try:
    if not SOURCE_PATH:
        # No default sample here (unlike NVD): KEV must come from a fetched folder or a named file.
        raise ValueError(
            "source_path is required: run scripts/fetch_kev.py on your laptop, upload the folder to "
            "/Volumes/workspace/vulnpulse_bronze/landing/kev/<batch_id>, and name it here."
        )

    # ---- 1. Read and explode ---------------------------------------------------------------
    # No window resolution, no gap check, no empty-window branch: there is always exactly one
    # file and it always holds the whole catalog. Compare the ~30 lines NVD needs for this step.
    catalog_df = bronze_kev.read_catalog(spark, READ_PATH)  # 1 row: the envelope
    entries = bronze_kev.explode_entries(catalog_df)  # ~1,700 rows: one per KEV entry
    rows_read = entries.count()

    # ---- 2. Shape and append ---------------------------------------------------------------
    bronze_df = bronze_kev.to_bronze(  # lift cveID, carry catalog_version, add hash + provenance
        entries,
        source_uri=SOURCE_URI,
        load_type="FULL",  # hard-coded: the only load type KEV has
        batch_id=BATCH_ID,
        load_timestamp=started_at,
    )
    bronze_kev.append(bronze_df, BRONZE_TABLE)  # append-only; each snapshot kept side by side
    # Count what actually landed in the table for this batch.
    rows_written = spark.table(BRONZE_TABLE).where(f"batch_id = '{BATCH_ID}'").count()

    # ---- 3. (NVD has "advance the watermark" here. KEV has nothing to advance.) -----------
    # Two consecutive KEV snapshots mostly repeat each other. That is expected: Silver's MERGE
    # keeps one row per CVE and updates it only when the newer snapshot actually changed it.

    # ---- 4. Purge the landing folder -------------------------------------------------------
    # Rows are in Bronze (the durable raw copy), so the uploaded files are redundant. Only a
    # volume folder is purged; a bare file path (e.g. the sample) is left alone.
    if is_folder and SOURCE_PATH.startswith("/Volumes/"):
        dbutils.fs.rm(SOURCE_PATH, True)  # FinOps: landing files are purged once in Bronze
    status = log.STATUS_SUCCESS
except Exception as exc:  # noqa: BLE001
    # Catch everything so the failure is recorded, then re-raise so the notebook/Job task fails.
    status = log.STATUS_FAILURE
    error = f"{type(exc).__name__}: {exc}"[:2000]
    raise
finally:
    # ---- 5. Audit row, written on every path ----------------------------------------------
    # Same columns as the NVD row. load_type is always FULL and source has no window suffix.
    # The manifest (with catalog_version) is copied into parameters so it survives the purge.
    log.append(
        log.build_log_row(
            spark,
            batch_id=BATCH_ID,
            layer=log.LAYER_RAW_TO_BRONZE,
            source=SOURCE_URI,
            load_type="FULL",
            parameters={"source_path": SOURCE_PATH, "catalog": CATALOG, "batch_id": BATCH_ID, "manifest": manifest},
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
    .where(f"batch_id = '{BATCH_ID}'")
    .select("layer", "load_type", "source", "status", "rows_read", "rows_inserted", "started_at")
)

# COMMAND ----------

# Snapshot history: one line per batch with CISA's catalog_version, so you can see the catalog
# grow (e.g. 1,734 entries at 2026.09.24 -> 1,748 at 2026.10.16). NVD shows load_type here instead.
display(
    spark.sql(
        f"SELECT batch_id, catalog_version, count(*) AS rows, min(load_timestamp) AS loaded_at "
        f"FROM {BRONZE_TABLE} GROUP BY batch_id, catalog_version ORDER BY loaded_at"
    )
)
