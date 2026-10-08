# Databricks notebook source
# MAGIC %load_ext autoreload
# MAGIC %autoreload 2

# COMMAND ----------

import os
import sys

SRC_PATH = os.path.abspath(os.path.join(os.getcwd(), "..", "src"))
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

spark.conf.set("spark.sql.session.timeZone", "UTC")
print("src:", SRC_PATH)

# COMMAND ----------

   import importlib
   importlib.invalidate_caches()

   from vulnpulse.silver import ddl

   tables = ddl.ensure_tables(spark, "workspace.vulnpulse_silver")
   print(tables)

# COMMAND ----------

tables = ensure_tables(spark, "workspace.vulnpulse_silver")
display(spark.sql(f"DESCRIBE TABLE {tables['silver_cve']}"))

# COMMAND ----------

from pyspark.sql import functions as F
from vulnpulse.silver import transform as tf
from vulnpulse.utils.params import utc_now

bronze = spark.table("workspace.vulnpulse_bronze.bronze_nvd_raw")
preview = tf.transform_nvd(bronze, load_timestamp=utc_now())

display(preview.drop("raw_json").limit(20))
display(preview.agg(
    F.count("*").alias("rows"),
    F.countDistinct("cve_id").alias("distinct_cves"),
    F.sum(F.col("cve_id").isNull().cast("int")).alias("null_id"),
    F.sum(F.col("published_at").isNull().cast("int")).alias("null_published"),
    F.sum(F.col("last_modified_at").isNull().cast("int")).alias("null_last_modified"),
    F.sum(F.col("cvss_v3_score").isNull().cast("int")).alias("null_score"),
    F.sum((F.size("unknown_keys") > 0).cast("int")).alias("rows_with_new_keys"),
))