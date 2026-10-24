# Databricks notebook source
# MAGIC %md
# MAGIC # 03 · Bronze-to-Silver: NVD, CISA KEV, affected products, CWEs
# MAGIC
# MAGIC Thin runner. Reads parameters, calls `vulnpulse.silver`, writes one `Bronze-to-Silver` audit row per
# MAGIC source, shows results. Every write is a `MERGE`, so re-running on the same Bronze changes nothing.
# MAGIC
# MAGIC | Widget | Standard run | Backfill |
# MAGIC |---|---|---|
# MAGIC | `batch_id` | blank (all Bronze) | one Bronze `batch_id` |
# MAGIC | `from_date` / `to_date` | blank | `YYYY-MM-DD`, inclusive, on Bronze `load_timestamp` (UTC) |
# MAGIC | `catalog` | `workspace` | `workspace` |
# MAGIC
# MAGIC Run cells: `silver_cve`, `silver_kev`, then (Phase 3) `silver_affected_product` and `silver_cwe`,
# MAGIC each with its own audit row. Failure drills live in `99_failure_drills`, not here.

# COMMAND ----------

# MAGIC %load_ext autoreload
# MAGIC %autoreload 2

# COMMAND ----------

import os
import sys

SRC_PATH = os.path.abspath(os.path.join(os.getcwd(), "..", "src"))
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

import importlib  # noqa: E402

importlib.invalidate_caches()

from pyspark.sql import functions as F  # noqa: E402

from vulnpulse.audit import execution_log as log  # noqa: E402
from vulnpulse.bronze.nvd import BRONZE_NVD_TABLE  # noqa: E402
from vulnpulse.silver import ddl, merge, quality  # noqa: E402
from vulnpulse.silver import transform as tf  # noqa: E402
from vulnpulse.silver.params import SilverRunParams, filter_bronze  # noqa: E402
from vulnpulse.utils.params import new_batch_id, utc_now  # noqa: E402

spark.conf.set("spark.sql.session.timeZone", "UTC")

# COMMAND ----------

dbutils.widgets.text("catalog", "workspace")
dbutils.widgets.text("batch_id", "")
dbutils.widgets.text("from_date", "")
dbutils.widgets.text("to_date", "")

params = SilverRunParams(
    catalog=dbutils.widgets.get("catalog").strip(),
    batch_id=dbutils.widgets.get("batch_id").strip() or None,
    from_date=dbutils.widgets.get("from_date").strip() or None,
    to_date=dbutils.widgets.get("to_date").strip() or None,
)

BRONZE_TABLE = f"{params.bronze_schema}.{BRONZE_NVD_TABLE}"
LOG_TABLE = f"{params.gold_schema}.{log.EXECUTION_LOG_TABLE}"
tables = ddl.ensure_tables(spark, params.silver_schema)
CVE_TABLE = tables[ddl.SILVER_CVE_TABLE]
QUARANTINE_TABLE = tables[ddl.SILVER_QUARANTINE_TABLE]

print("parameters:", params.as_dict(), "->", params.load_type)
print("bronze:", BRONZE_TABLE, "| silver:", CVE_TABLE, "| log:", LOG_TABLE)

# COMMAND ----------

run_id = new_batch_id()  # unique per execution of this cell
started_at = utc_now()
rows_read = inserted = updated = quarantined = 0
drift_keys = []
error = None

try:
    bronze = filter_bronze(spark.table(BRONZE_TABLE), params)
    rows_read = bronze.count()

    shaped = tf.transform_nvd(bronze, load_timestamp=started_at)
    drift_keys = sorted(
        r["k"] for r in shaped.select(F.explode("unknown_keys").alias("k")).distinct().collect()
    )

    valid, bad = quality.split_valid_invalid(shaped, quality.nvd_rules(), source_table=BRONZE_TABLE)
    latest = merge.dedup_latest(
        valid, "cve_id", ["last_modified_at", "batch_id", "payload_sha256"]
    ).select(*tf.SILVER_CVE_COLUMNS)

    cve_counts = merge.merge_upsert(
        spark, latest, CVE_TABLE, key="cve_id", update_condition=merge.CVE_UPDATE_CONDITION
    )
    inserted, updated = cve_counts["inserted"], cve_counts["updated"]
    # Counts recorded before the quarantine MERGE: if that step fails, the audit row still
    # reports what the CVE MERGE actually did (incident 9 Oct 2026, see docs/EVIDENCE.md).
    q_counts = merge.merge_quarantine(spark, bad, QUARANTINE_TABLE)
    quarantined = q_counts["inserted"]
    status = log.STATUS_SUCCESS
except Exception as exc:  # noqa: BLE001 - logged then re-raised
    status = log.STATUS_FAILURE
    error = f"{type(exc).__name__}: {exc}"[:2000]
    raise
finally:
    log.append(
        log.build_log_row(
            spark,
            batch_id=run_id,
            layer=log.LAYER_BRONZE_TO_SILVER,
            source=f"{BRONZE_TABLE} -> {CVE_TABLE}",
            load_type=params.load_type,
            parameters={**params.as_dict(), "run_id": run_id, "schema_drift_keys": drift_keys},
            started_at=started_at,
            finished_at=utc_now(),
            status=status,
            rows_read=rows_read,
            rows_inserted=inserted,
            rows_updated=updated,
            rows_quarantined=quarantined,
            error_message=error,
        ),
        LOG_TABLE,
    )

print(
    f"{status}: read {rows_read}, inserted {inserted}, updated {updated}, "
    f"quarantined {quarantined}, schema drift keys {drift_keys or 'none'}"
)

# COMMAND ----------

display(
    spark.table(LOG_TABLE)
    .where(F.col("layer") == log.LAYER_BRONZE_TO_SILVER)
    .orderBy(F.col("started_at").desc())
    .select(
        "batch_id", "load_type", "status", "rows_read", "rows_inserted", "rows_updated",
        "rows_quarantined", "started_at", "finished_at",
    )
    .limit(5)
)
display(
    spark.sql(
        f"SELECT count(*) AS silver_rows, count(DISTINCT cve_id) AS distinct_cves FROM {CVE_TABLE}"
    )
)

# COMMAND ----------

from vulnpulse.bronze.kev import BRONZE_KEV_TABLE  # noqa: E402
from vulnpulse.silver import kev as kev_tf  # noqa: E402

BRONZE_KEV = f"{params.bronze_schema}.{BRONZE_KEV_TABLE}"
KEV_TABLE = tables[ddl.SILVER_KEV_TABLE]

run_id = new_batch_id()  # unique per execution of this cell
started_at = utc_now()
rows_read = inserted = updated = quarantined = 0
drift_keys = []
error = None

try:
    bronze = filter_bronze(spark.table(BRONZE_KEV), params)
    rows_read = bronze.count()

    shaped = kev_tf.transform_kev(bronze, load_timestamp=started_at)
    drift_keys = sorted(
        r["k"] for r in shaped.select(F.explode("unknown_keys").alias("k")).distinct().collect()
    )

    valid, bad = quality.split_valid_invalid(shaped, quality.kev_rules(), source_table=BRONZE_KEV)
    latest = merge.dedup_latest(valid, "cve_id", kev_tf.KEV_DEDUP_ORDER).select(
        *kev_tf.SILVER_KEV_COLUMNS
    )

    kev_counts = merge.merge_upsert(
        spark, latest, KEV_TABLE, key="cve_id", update_condition=merge.KEV_UPDATE_CONDITION
    )
    inserted, updated = kev_counts["inserted"], kev_counts["updated"]
    # Counts recorded before the quarantine MERGE: if that step fails, the audit row still
    # reports what the CVE MERGE actually did (incident 9 Oct 2026, see docs/EVIDENCE.md).
    q_counts = merge.merge_quarantine(spark, bad, QUARANTINE_TABLE)
    quarantined = q_counts["inserted"]
    status = log.STATUS_SUCCESS
except Exception as exc:  # noqa: BLE001 - logged then re-raised
    status = log.STATUS_FAILURE
    error = f"{type(exc).__name__}: {exc}"[:2000]
    raise
finally:
    log.append(
        log.build_log_row(
            spark,
            batch_id=run_id,
            layer=log.LAYER_BRONZE_TO_SILVER,
            source=f"{BRONZE_KEV} -> {KEV_TABLE}",
            load_type=params.load_type,
            parameters={**params.as_dict(), "run_id": run_id, "schema_drift_keys": drift_keys},
            started_at=started_at,
            finished_at=utc_now(),
            status=status,
            rows_read=rows_read,
            rows_inserted=inserted,
            rows_updated=updated,
            rows_quarantined=quarantined,
            error_message=error,
        ),
        LOG_TABLE,
    )

print(
    f"KEV {status}: read {rows_read}, inserted {inserted}, updated {updated}, "
    f"quarantined {quarantined}, schema drift keys {drift_keys or 'none'}"
)
display(
    spark.sql(
        f"SELECT count(*) AS kev_rows, count(DISTINCT cve_id) AS distinct_cves, "
        f"min(date_added) AS first_added, max(date_added) AS last_added FROM {KEV_TABLE}"
    )
)

# COMMAND ----------

# MAGIC %md
# MAGIC ## Phase 3: child tables `silver_affected_product` and `silver_cwe`
# MAGIC
# MAGIC Same pattern as `silver_cve`: latest Bronze version per CVE, typed explode, quality rules,
# MAGIC dedup on the composite key, `MERGE` (update only when the CVE's `lastModified` is newer),
# MAGIC quarantine with a reason, one `Bronze-to-Silver` audit row per table.

# COMMAND ----------

from vulnpulse.silver import cwe as cwe_tf  # noqa: E402
from vulnpulse.silver import products as product_tf  # noqa: E402

CHILD_TABLES = (
    # target table, module, composite key, quarantine source label
    (tables[ddl.SILVER_AFFECTED_PRODUCT_TABLE], product_tf, product_tf.PRODUCT_KEY, "cpe"),
    (tables[ddl.SILVER_CWE_TABLE], cwe_tf, cwe_tf.CWE_KEY, "cwe"),
)

for target, module, key, label in CHILD_TABLES:
    run_id = new_batch_id()  # unique per table per execution of this cell
    started_at = utc_now()
    rows_read = inserted = updated = quarantined = 0
    error = None
    try:
        bronze = filter_bronze(spark.table(BRONZE_TABLE), params)
        if module is product_tf:
            shaped = product_tf.transform_products(bronze, load_timestamp=started_at)
        else:
            shaped = cwe_tf.transform_cwe(bronze, load_timestamp=started_at)
        rows_read = shaped.count()  # exploded child rows considered

        latest, bad = module.split_and_dedup(shaped, source_table=f"{BRONZE_TABLE}#{label}")
        counts = merge.merge_upsert(
            spark, latest, target, key=key, update_condition=merge.CVE_UPDATE_CONDITION
        )
        inserted, updated = counts["inserted"], counts["updated"]
        quarantined = merge.merge_quarantine(spark, bad, QUARANTINE_TABLE)["inserted"]
        status = log.STATUS_SUCCESS
    except Exception as exc:  # noqa: BLE001 - logged then re-raised
        status = log.STATUS_FAILURE
        error = f"{type(exc).__name__}: {exc}"[:2000]
        raise
    finally:
        log.append(
            log.build_log_row(
                spark,
                batch_id=run_id,
                layer=log.LAYER_BRONZE_TO_SILVER,
                source=f"{BRONZE_TABLE} -> {target}",
                load_type=params.load_type,
                parameters={**params.as_dict(), "run_id": run_id},
                started_at=started_at,
                finished_at=utc_now(),
                status=status,
                rows_read=rows_read,
                rows_inserted=inserted,
                rows_updated=updated,
                rows_quarantined=quarantined,
                error_message=error,
            ),
            LOG_TABLE,
        )
    print(
        f"{target.split('.')[-1]} {status}: read {rows_read}, inserted {inserted}, "
        f"updated {updated}, quarantined {quarantined}"
    )

# COMMAND ----------

display(
    spark.sql(
        f"""
        SELECT 'silver_affected_product' AS table_name, count(*) AS rows,
               count(DISTINCT cve_id) AS cves,
               count(DISTINCT concat(vendor, '|', product)) AS vendor_products,
               sum(CAST(vulnerable AS INT)) AS vulnerable_rows
        FROM {tables[ddl.SILVER_AFFECTED_PRODUCT_TABLE]}
        UNION ALL
        SELECT 'silver_cwe', count(*), count(DISTINCT cve_id), count(DISTINCT cwe_id), NULL
        FROM {tables[ddl.SILVER_CWE_TABLE]}
        """
    )
)
display(
    spark.sql(
        f"SELECT source_table, reason, count(*) AS n FROM {QUARANTINE_TABLE} "
        f"GROUP BY source_table, reason ORDER BY n DESC"
    )
)
