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
# MAGIC ## 3. CVE core: `dim_cve` and `fact_cve` (MERGE, idempotent)
# MAGIC
# MAGIC Reads `silver_cve` and `silver_kev` (and `silver_affected_product` / `silver_cwe` for per-CVE
# MAGIC counts when they exist). In `incremental` mode only CVEs with Silver rows loaded after the Gold
# MAGIC watermark are rebuilt; `full` mode (or the first run) rebuilds every CVE. The watermark advances
# MAGIC only after all MERGEs succeed.

# COMMAND ----------

from vulnpulse.gold import cve as gold_cve  # noqa: E402
from vulnpulse.gold import merge as gold_merge  # noqa: E402
from vulnpulse.gold import run as gold_run  # noqa: E402
from vulnpulse.utils import watermark as wm  # noqa: E402

WATERMARK_TABLE = f"{GOLD}.{wm.WATERMARK_TABLE}"
wm.ensure_table(spark, WATERMARK_TABLE)

silver_frames = gold_run.existing_silver_frames(spark, SILVER)
print("silver tables present:", ", ".join(silver_frames))
silver_cve_all = silver_frames["silver_cve"]
silver_kev = silver_frames["silver_kev"]

# Scope: in incremental mode only CVEs touched in Silver since the Gold watermark.
gold_wm = gold_run.read_gold_watermark(spark, WATERMARK_TABLE)
print("gold watermark before run:", gold_wm)
if MODE == "full" or gold_wm is None:
    changed = None
    print("scope: all CVEs", "(full rebuild)" if MODE == "full" else "(first run, no watermark yet)")
else:
    changed = gold_run.changed_cve_ids(list(silver_frames.values()), since=gold_wm)
    print(f"scope: {changed.count()} CVEs with Silver changes after the watermark")

silver_cve = gold_run.scope_to(silver_cve_all, changed)


def optional_counts(table: str):
    if table in silver_frames:
        print(f"child counts from {SILVER}.{table}")
        return gold_cve.count_per_cve(gold_run.scope_to(silver_frames[table], changed))
    print(f"{SILVER}.{table} not present yet; count column will be NULL")
    return None


product_counts = optional_counts("silver_affected_product")
cwe_counts = optional_counts("silver_cwe")

rows_in = silver_cve.count()
print(f"silver_cve rows in scope: {rows_in}; silver_kev rows: {silver_kev.count()}")

# COMMAND ----------

for name, build in (
    ("dim_cve", lambda ts: gold_cve.build_dim_cve(silver_cve, silver_kev, batch_id=RUN_ID, load_timestamp=ts)),
    (
        "fact_cve",
        lambda ts: gold_cve.build_fact_cve(
            silver_cve,
            silver_kev,
            batch_id=RUN_ID,
            load_timestamp=ts,
            product_counts=product_counts,
            cwe_counts=cwe_counts,
        ),
    ),
):
    started = utc_now()
    error = None
    counts = {}
    try:
        counts = gold_merge.merge_gold(spark, build(started), tables[name], keys=["cve_id"])
        print(f"{name}: read {rows_in}, inserted {counts['inserted']}, updated {counts['updated']}")
    except Exception as exc:  # noqa: BLE001 - logged then re-raised
        error = f"{type(exc).__name__}: {exc}"[:2000]
        raise
    finally:
        log_gold_write(tables[name], started, rows_in, counts, error)

# Advance the Gold watermark only now, after every MERGE above succeeded (contract rule 24).
new_wm = gold_run.max_load_timestamp(list(silver_frames.values()))
if new_wm is not None and (gold_wm is None or new_wm > gold_wm):
    gold_run.write_gold_watermark(spark, WATERMARK_TABLE, new_wm, RUN_ID)
    print("gold watermark after run: ", new_wm)
else:
    print("gold watermark unchanged:  ", gold_wm, "(no newer Silver rows)")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Results

# COMMAND ----------

display(
    spark.sql(f"SHOW TABLES IN {GOLD}").select("tableName", "isTemporary").orderBy("tableName")
)

# COMMAND ----------

display(
    spark.sql(
        f"""
        SELECT s.severity, count(*) AS cves, sum(f.is_exploited) AS exploited,
               round(avg(f.cvss_v3_score), 2) AS avg_score
        FROM {GOLD}.fact_cve f JOIN {GOLD}.dim_severity s ON s.severity_key = f.severity_key
        GROUP BY s.severity, s.sort_order ORDER BY s.sort_order
        """
    )
)
display(
    spark.sql(
        f"""
        SELECT count(*) AS fact_rows, count(DISTINCT cve_id) AS distinct_cves,
               sum(is_exploited) AS in_kev, sum(is_ransomware) AS ransomware,
               percentile_approx(days_to_kev, 0.5) AS median_days_to_kev,
               min(days_to_kev) AS min_days_to_kev, max(days_to_kev) AS max_days_to_kev
        FROM {GOLD}.fact_cve
        """
    )
)
display(spark.sql(f"SELECT count(*) AS watchlist_rows FROM {GOLD}.{ddl.WATCHLIST_VIEW}"))

# COMMAND ----------

display(spark.table(WATERMARK_TABLE).orderBy("load_timestamp", ascending=False).limit(10))

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
