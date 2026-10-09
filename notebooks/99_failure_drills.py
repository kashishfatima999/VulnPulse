# Databricks notebook source
# MAGIC %md
# MAGIC # 99 · Silver failure drills (demo, not production)
# MAGIC
# MAGIC Proves the Phase 2 robustness rules on **scratch copies** of the Silver tables
# MAGIC (`drill_silver_cve`, `drill_silver_quarantine`), so production Silver is never touched.
# MAGIC Run `03_silver` first so the copies start from real data.
# MAGIC
# MAGIC | Drill | Injected Bronze row | Expected |
# MAGIC |---|---|---|
# MAGIC | D1 | Existing CVE with a newer `lastModified` | `MERGE` updates it (`updated 1`) |
# MAGIC | D2 | Record with no `cve_id` | Quarantined as `missing_cve_id`, batch continues |
# MAGIC | D3 | Unparseable `published` date | Quarantined as `unparseable_published`, batch continues |
# MAGIC | D4 | New top-level field + CVSS score sent as a string | Drift key logged, score cast to DOUBLE, row inserted |

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

from vulnpulse.bronze.nvd import BRONZE_NVD_TABLE  # noqa: E402
from vulnpulse.silver import ddl, merge, quality  # noqa: E402
from vulnpulse.silver import transform as tf  # noqa: E402
from vulnpulse.silver.params import SilverRunParams  # noqa: E402
from vulnpulse.utils.params import utc_now  # noqa: E402

spark.conf.set("spark.sql.session.timeZone", "UTC")

dbutils.widgets.text("catalog", "workspace")
params = SilverRunParams(catalog=dbutils.widgets.get("catalog").strip())

BRONZE_TABLE = f"{params.bronze_schema}.{BRONZE_NVD_TABLE}"
tables = ddl.ensure_tables(spark, params.silver_schema)
CVE_TABLE = tables[ddl.SILVER_CVE_TABLE]
QUARANTINE_TABLE = tables[ddl.SILVER_QUARANTINE_TABLE]

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
