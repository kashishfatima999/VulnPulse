# Databricks notebook source
# /// script
# [tool.databricks.environment]
# environment_version = "6"
# ///
# MAGIC %md
# MAGIC # 02 · Raw-to-Bronze: CISA KEV
# MAGIC
# MAGIC The KEV catalog has no incremental API, so every run is a FULL snapshot of the live feed.
# MAGIC
# MAGIC | Widget | Meaning |
# MAGIC |---|---|
# MAGIC | `source_path` | blank = download the live catalog into the landing volume; or a file path to read instead |
# MAGIC | `batch_id` | blank = auto |
# MAGIC | `catalog` | Unity Catalog catalog, default `workspace` |

# COMMAND ----------

import os
import sys

SRC_PATH = os.path.abspath(os.path.join(os.getcwd(), "..", "src"))
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

from vulnpulse.audit import execution_log as log  # noqa: E402
from vulnpulse.bronze import kev as bronze_kev  # noqa: E402
from vulnpulse.utils.params import new_batch_id, utc_now  # noqa: E402

spark.conf.set("spark.sql.session.timeZone", "UTC")

# COMMAND ----------

dbutils.widgets.text("source_path", "")
dbutils.widgets.text("batch_id", "")
dbutils.widgets.text("catalog", "workspace")

CATALOG = dbutils.widgets.get("catalog").strip() or "workspace"
BATCH_ID = dbutils.widgets.get("batch_id").strip() or new_batch_id()
SOURCE_PATH = dbutils.widgets.get("source_path").strip() or None

BRONZE_TABLE = f"{CATALOG}.vulnpulse_bronze.{bronze_kev.BRONZE_KEV_TABLE}"
LOG_TABLE = f"{CATALOG}.vulnpulse_gold.{log.EXECUTION_LOG_TABLE}"
LANDING_FILE = f"/Volumes/{CATALOG}/vulnpulse_bronze/landing/kev/{BATCH_ID}/known_exploited_vulnerabilities.json"

print("batch_id:    ", BATCH_ID)
print("source:      ", SOURCE_PATH or bronze_kev.KEV_URL)
print("bronze table:", BRONZE_TABLE)

# COMMAND ----------

bronze_kev.ensure_table(spark, BRONZE_TABLE)
log.ensure_table(spark, LOG_TABLE)

# COMMAND ----------

started_at = utc_now()
rows_read = rows_written = 0
error = None

try:
    if SOURCE_PATH:
        source_uri, read_path = SOURCE_PATH, SOURCE_PATH
    else:
        source_uri = bronze_kev.KEV_URL
        read_path = bronze_kev.download_catalog(LANDING_FILE)
        print("downloaded to", read_path)

    catalog_df = bronze_kev.read_catalog(spark, read_path)
    entries = bronze_kev.explode_entries(catalog_df)
    rows_read = entries.count()

    bronze_df = bronze_kev.to_bronze(
        entries,
        source_uri=source_uri,
        load_type="FULL",
        batch_id=BATCH_ID,
        load_timestamp=started_at,
    )
    bronze_kev.append(bronze_df, BRONZE_TABLE)
    rows_written = spark.table(BRONZE_TABLE).where(f"batch_id = '{BATCH_ID}'").count()

    if not SOURCE_PATH:
        dbutils.fs.rm(os.path.dirname(LANDING_FILE), True)
    status = log.STATUS_SUCCESS
except Exception as exc:  # noqa: BLE001
    status = log.STATUS_FAILURE
    error = f"{type(exc).__name__}: {exc}"[:2000]
    raise
finally:
    log.append(
        log.build_log_row(
            spark,
            batch_id=BATCH_ID,
            layer=log.LAYER_RAW_TO_BRONZE,
            source=SOURCE_PATH or bronze_kev.KEV_URL,
            load_type="FULL",
            parameters={"source_path": SOURCE_PATH, "catalog": CATALOG, "batch_id": BATCH_ID},
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
    .where(f"batch_id = '{BATCH_ID}'")
    .select("layer", "load_type", "source", "status", "rows_read", "rows_inserted", "started_at")
)

# COMMAND ----------

display(
    spark.sql(
        f"SELECT batch_id, catalog_version, count(*) AS rows, min(load_timestamp) AS loaded_at "
        f"FROM {BRONZE_TABLE} GROUP BY batch_id, catalog_version ORDER BY loaded_at"
    )
)
