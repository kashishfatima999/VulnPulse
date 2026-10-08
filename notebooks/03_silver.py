# Databricks notebook source
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
from vulnpulse.utils.params import utc_now  # noqa: E402

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
    q_counts = merge.merge_quarantine(spark, bad, QUARANTINE_TABLE)
    inserted, updated = cve_counts["inserted"], cve_counts["updated"]
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
            batch_id=params.run_id,
            layer=log.LAYER_BRONZE_TO_SILVER,
            source=f"{BRONZE_TABLE} -> {CVE_TABLE}",
            load_type=params.load_type,
            parameters={**params.as_dict(), "schema_drift_keys": drift_keys},
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
    q_counts = merge.merge_quarantine(spark, bad, QUARANTINE_TABLE)
    inserted, updated = kev_counts["inserted"], kev_counts["updated"]
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
            batch_id=params.run_id + "-kev",
            layer=log.LAYER_BRONZE_TO_SILVER,
            source=f"{BRONZE_KEV} -> {KEV_TABLE}",
            load_type=params.load_type,
            parameters={**params.as_dict(), "schema_drift_keys": drift_keys},
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

# Failure drills on scratch copies of the Silver tables, so real Silver stays clean.
DRILL_CVE = f"{params.silver_schema}.drill_silver_cve"
DRILL_QUARANTINE = f"{params.silver_schema}.drill_silver_quarantine"
spark.sql(f"CREATE OR REPLACE TABLE {DRILL_CVE} AS SELECT * FROM {CVE_TABLE}")
spark.sql(f"CREATE OR REPLACE TABLE {DRILL_QUARANTINE} AS SELECT * FROM {QUARANTINE_TABLE}")

# One real Bronze row that has a CVSS v3.1 score, picked deterministically.
base = (
    spark.table(BRONZE_TABLE)
    .where(
        F.get_json_object("raw_json", "$.metrics.cvssMetricV31[0].cvssData.baseScore").isNotNull()
    )
    .orderBy("cve_id", "batch_id")
    .limit(1)
)
LAST_MOD = r'"lastModified"\s*:\s*"[^"]+"'
PUBLISHED = r'"published"\s*:\s*"[^"]+"'
SCORE = r'"baseScore"\s*:\s*([0-9.]+)'

drill_bronze = (
    # D1: newer version of a CVE already in Silver -> expect UPDATE
    base.withColumn(
        "raw_json",
        F.regexp_replace("raw_json", LAST_MOD, '"lastModified":"2030-01-01T00:00:00.000"'),
    )
    .withColumn("batch_id", F.lit("drill-update"))
    # D2: record with no id -> quarantine (missing_cve_id)
    .unionByName(
        base.withColumn("cve_id", F.lit(None).cast("string")).withColumn(
            "batch_id", F.lit("drill-missing-id")
        )
    )
    # D3: unparseable date -> quarantine (unparseable_published)
    .unionByName(
        base.withColumn("cve_id", F.lit("CVE-2099-0001"))
        .withColumn("raw_json", F.regexp_replace("raw_json", PUBLISHED, '"published":"not-a-date"'))
        .withColumn("batch_id", F.lit("drill-bad-date"))
    )
    # D4: schema drift -> new top-level field + score sent as a string; must still load
    .unionByName(
        base.withColumn("cve_id", F.lit("CVE-2099-0002"))
        .withColumn(
            "raw_json",
            F.concat(
                F.lit('{"cveNewField":"drift-test",'),
                F.expr("substring(raw_json, 2)"),
            ),
        )
        .withColumn("raw_json", F.regexp_replace("raw_json", SCORE, '"baseScore":"$1"'))
        .withColumn("batch_id", F.lit("drill-drift"))
    )
)

shaped = tf.transform_nvd(drill_bronze, load_timestamp=utc_now())
drift = sorted(
    r["k"] for r in shaped.select(F.explode("unknown_keys").alias("k")).distinct().collect()
)
valid, bad = quality.split_valid_invalid(shaped, quality.nvd_rules(), source_table=BRONZE_TABLE)
latest = merge.dedup_latest(
    valid, "cve_id", ["last_modified_at", "batch_id", "payload_sha256"]
).select(*tf.SILVER_CVE_COLUMNS)
c = merge.merge_upsert(
    spark, latest, DRILL_CVE, key="cve_id", update_condition=merge.CVE_UPDATE_CONDITION
)
q = merge.merge_quarantine(spark, bad, DRILL_QUARANTINE)
print(
    f"inserted {c['inserted']}, updated {c['updated']}, quarantined {q['inserted']}, drift {drift}"
)

display(spark.table(DRILL_QUARANTINE).select("cve_id", "reason", "batch_id").orderBy("batch_id"))
display(
    spark.table(DRILL_CVE)
    .where(F.col("cve_id").isin("CVE-2099-0002") | F.col("batch_id").startswith("drill"))
    .select("cve_id", "last_modified_at", "cvss_v3_score", "cvss_v3_severity", "batch_id")
)