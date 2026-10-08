"""Deduplicate and MERGE INTO the Silver tables.

Idempotency (contract rules 7 and 8): the source is deduplicated on the natural key, keeping the
latest version, and a matched target row is only updated when the source is strictly newer. Re-
running the same Bronze data therefore inserts 0 rows and updates 0 rows.
"""

from __future__ import annotations

from pyspark.sql import DataFrame, SparkSession, Window
from pyspark.sql import functions as F

from vulnpulse.silver.quality import QUARANTINE_COLUMNS

# A matched silver_cve row changes only when NVD modified the CVE after the version we hold.
CVE_UPDATE_CONDITION = "s.last_modified_at > t.last_modified_at"
# KEV has no modification timestamp: update when the entry's content changed in a newer catalog.
KEV_UPDATE_CONDITION = (
    "s.payload_sha256 <> t.payload_sha256 AND s.catalog_version >= t.catalog_version"
)


def dedup_latest(df: DataFrame, key: str, order_by: list[str]) -> DataFrame:
    """One row per ``key``: the first row when sorted by ``order_by`` descending.

    Callers pass enough tie-breakers (batch_id, payload_sha256) that the pick is deterministic,
    so the same input always yields the same winner.
    """
    window = Window.partitionBy(key).orderBy(*[F.col(c).desc_nulls_last() for c in order_by])
    return df.withColumn("_rn", F.row_number().over(window)).where("_rn = 1").drop("_rn")


def merge_upsert(
    spark: SparkSession,
    source: DataFrame,
    target_fqn: str,
    *,
    key: str,
    update_condition: str,
    view_name: str = "_silver_merge_source",
) -> dict[str, int]:
    """``MERGE INTO`` target on ``key``. Returns ``{"inserted": n, "updated": n}``."""
    source.createOrReplaceTempView(view_name)
    result = spark.sql(
        f"""
        MERGE INTO {target_fqn} AS t
        USING {view_name} AS s
        ON t.{key} = s.{key}
        WHEN MATCHED AND {update_condition} THEN UPDATE SET *
        WHEN NOT MATCHED THEN INSERT *
        """
    )
    return _merge_counts(spark, result, target_fqn)


def merge_quarantine(spark: SparkSession, quarantine: DataFrame, target_fqn: str) -> dict[str, int]:
    """Insert-only MERGE so a re-run never duplicates quarantine rows."""
    keys = ["source_table", "batch_id", "payload_sha256", "reason"]
    source = quarantine.select(*QUARANTINE_COLUMNS).dropDuplicates(keys)
    source.createOrReplaceTempView("_silver_quarantine_source")
    on = " AND ".join(f"t.{k} = s.{k}" for k in keys)
    result = spark.sql(
        f"""
        MERGE INTO {target_fqn} AS t
        USING _silver_quarantine_source AS s
        ON {on}
        WHEN NOT MATCHED THEN INSERT *
        """
    )
    return _merge_counts(spark, result, target_fqn)


def _merge_counts(spark: SparkSession, result: DataFrame, target_fqn: str) -> dict[str, int]:
    """Databricks returns the counts as the MERGE result; fall back to the Delta history."""
    row = result.first()
    if row is not None and "num_inserted_rows" in row.asDict():
        values = row.asDict()
        return {
            "inserted": int(values.get("num_inserted_rows") or 0),
            "updated": int(values.get("num_updated_rows") or 0),
        }
    metrics = (
        spark.sql(f"DESCRIBE HISTORY {target_fqn} LIMIT 1").select("operationMetrics").first()[0]
    )
    return {
        "inserted": int(metrics.get("numTargetRowsInserted", 0)),
        "updated": int(metrics.get("numTargetRowsUpdated", 0)),
    }