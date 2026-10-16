# Databricks notebook source
# /// script
# [tool.databricks.environment]
# environment_version = "6"
# ///
# MAGIC %md
# MAGIC # 04 · Silver-to-Gold: star schema
# MAGIC
# MAGIC Thin runner. Creates the Gold star schema (idempotent DDL with liquid clustering and
# MAGIC informational PK/FK constraints), rebuilds the static dimensions, then refreshes the Silver-derived
# MAGIC dimensions and facts with MERGE. Every table write logs a `Silver-to-Gold` row.
# MAGIC
# MAGIC | Widget | Meaning |
# MAGIC |---|---|
# MAGIC | `mode` | `incremental` = only Silver rows newer than the Gold watermark; `full` = rebuild from all of Silver (backfill) |
# MAGIC | `run_id` | blank = auto. Shared `batch_id` for every Gold row written by this run |
# MAGIC | `catalog` | Unity Catalog catalog, default `workspace` |
# MAGIC
# MAGIC Session 1 scope: DDL, constraints, view, `dim_date`, `dim_severity`. Later cells add the rest.

# COMMAND ----------

# MAGIC %load_ext autoreload
# MAGIC %autoreload 2

# COMMAND ----------

import os
import sys

SRC_PATH = os.path.abspath(os.path.join(os.getcwd(), "..", "src"))
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

from pyspark.sql import functions as F  # noqa: E402

from vulnpulse.audit import execution_log as log  # noqa: E402
from vulnpulse.gold import ddl, dims_static  # noqa: E402
from vulnpulse.utils.params import new_batch_id, utc_now  # noqa: E402

spark.conf.set("spark.sql.session.timeZone", "UTC")

# COMMAND ----------

dbutils.widgets.dropdown("mode", "incremental", ["incremental", "full"])
dbutils.widgets.text("run_id", "")
dbutils.widgets.text("catalog", "workspace")

MODE = dbutils.widgets.get("mode")
RUN_ID = dbutils.widgets.get("run_id").strip() or new_batch_id()
CATALOG = dbutils.widgets.get("catalog").strip() or "workspace"

GOLD = f"{CATALOG}.vulnpulse_gold"
SILVER = f"{CATALOG}.vulnpulse_silver"
LOG_TABLE = f"{GOLD}.{log.EXECUTION_LOG_TABLE}"

print("mode:  ", MODE)
print("run_id:", RUN_ID)
print("gold:  ", GOLD, "| silver:", SILVER, "| log:", LOG_TABLE)

# COMMAND ----------

# MAGIC %md
# MAGIC ## 1. Schema: tables, constraints, view

# COMMAND ----------

tables = ddl.ensure_tables(spark, GOLD)
for fqn in tables.values():
    print(f"table ready: {fqn}")

constraints = ddl.ensure_constraints(spark, GOLD)
for name, outcome in constraints.items():
    print(f"  constraint {name:<42} {outcome}")

print("view ready:", ddl.ensure_watchlist_view(spark, GOLD))


def log_gold_write(target: str, started_at, rows_read: int, counts: dict, error=None) -> None:
    """One Silver-to-Gold audit row per table write (contract rule 25)."""
    log.append(
        log.build_log_row(
            spark,
            batch_id=RUN_ID,
            layer=log.LAYER_SILVER_TO_GOLD,
            source=target,
            load_type="FULL" if MODE == "full" else "INCREMENTAL",
            parameters={"mode": MODE, "run_id": RUN_ID, "catalog": CATALOG},
            started_at=started_at,
            finished_at=utc_now(),
            status=log.STATUS_FAILURE if error else log.STATUS_SUCCESS,
            rows_read=rows_read,
            rows_inserted=counts.get("inserted", 0),
            rows_updated=counts.get("updated", 0),
            rows_quarantined=0,
            error_message=error,
        ),
        LOG_TABLE,
    )


# COMMAND ----------

# MAGIC %md
# MAGIC ## 2. Static dimensions (generated, overwritten every run)

# COMMAND ----------

for name, builder in (
    ("dim_date", dims_static.build_dim_date),
    ("dim_severity", dims_static.build_dim_severity),
):
    started = utc_now()
    error = None
    written = 0
    try:
        df = builder(spark, batch_id=RUN_ID, load_timestamp=started)
        written = dims_static.overwrite(df, tables[name])
        print(f"{name}: {written} rows written")
    except Exception as exc:  # noqa: BLE001 - logged then re-raised
        error = f"{type(exc).__name__}: {exc}"[:2000]
        raise
    finally:
        log_gold_write(tables[name], started, written, {"inserted": written, "updated": 0}, error)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Results

# COMMAND ----------

display(
    spark.sql(f"SHOW TABLES IN {GOLD}").select("tableName", "isTemporary").orderBy("tableName")
)

# COMMAND ----------

display(
    spark.table(tables["dim_date"])
    .groupBy("year")
    .agg(F.count("*").alias("days"), F.sum(F.col("is_weekend").cast("int")).alias("weekend_days"))
    .orderBy("year")
    .limit(5)
)
display(spark.table(tables["dim_severity"]).orderBy("sort_order"))

# COMMAND ----------

display(
    spark.table(LOG_TABLE)
    .where(F.col("layer") == log.LAYER_SILVER_TO_GOLD)
    .where(F.col("batch_id") == RUN_ID)
    .select("source", "load_type", "status", "rows_read", "rows_inserted", "started_at", "finished_at")
)
