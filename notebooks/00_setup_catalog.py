# Databricks notebook source
# MAGIC %md
# MAGIC # 00 · Setup catalog
# MAGIC
# MAGIC Creates the Unity Catalog objects the pipeline writes to. Safe to run as many times as you
# MAGIC like: everything is `IF NOT EXISTS`.
# MAGIC
# MAGIC | Object | Purpose |
# MAGIC |---|---|
# MAGIC | `<catalog>.vulnpulse_bronze` | Raw NVD and KEV payloads (append-only Delta) |
# MAGIC | `<catalog>.vulnpulse_silver` | Cleansed, typed, deduplicated tables |
# MAGIC | `<catalog>.vulnpulse_gold` | Aggregates and the pipeline audit / watermark table |
# MAGIC | `<catalog>.vulnpulse_bronze.landing` | Volume for downloaded feed files before Bronze reads them |

# COMMAND ----------

# Make the repository's src/ importable. Databricks runs a notebook with its own folder as the
# working directory, so ../src is the package root when this notebook lives in notebooks/.
import os
import sys

SRC_PATH = os.path.abspath(os.path.join(os.getcwd(), "..", "src"))
if SRC_PATH not in sys.path:
    sys.path.insert(0, SRC_PATH)

import vulnpulse  # noqa: E402

print(f"vulnpulse package {vulnpulse.__version__} imported from {SRC_PATH}")

# COMMAND ----------

dbutils.widgets.text("catalog", "workspace", "Unity Catalog catalog")
CATALOG = dbutils.widgets.get("catalog").strip()

SCHEMAS = ["vulnpulse_bronze", "vulnpulse_silver", "vulnpulse_gold"]
LANDING_VOLUME = f"{CATALOG}.vulnpulse_bronze.landing"

print(f"Spark {spark.version}")
print(f"Catalog: {CATALOG}")

# COMMAND ----------

for schema in SCHEMAS:
    spark.sql(f"CREATE SCHEMA IF NOT EXISTS {CATALOG}.{schema}")
    print(f"schema ready: {CATALOG}.{schema}")

spark.sql(f"CREATE VOLUME IF NOT EXISTS {LANDING_VOLUME}")
print(f"volume ready: {LANDING_VOLUME}")

# COMMAND ----------

# MAGIC %md
# MAGIC ## Verify

# COMMAND ----------

display(spark.sql(f"SHOW SCHEMAS IN {CATALOG} LIKE 'vulnpulse*'"))

# COMMAND ----------

display(spark.sql(f"SHOW VOLUMES IN {CATALOG}.vulnpulse_bronze"))

# COMMAND ----------

# The volume is reachable as a normal path. Nothing is written yet; this only lists it.
volume_path = f"/Volumes/{CATALOG}/vulnpulse_bronze/landing"
print(volume_path, "->", dbutils.fs.ls(volume_path))
