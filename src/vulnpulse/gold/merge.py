"""MERGE helpers for Gold.

Dimensions are SCD type 1 and facts are upserts on their declared key. In both cases a matched row
is updated only when a *business* column differs. `batch_id` and `load_timestamp` are excluded from
the comparison, otherwise every run would rewrite every row and the "re-run changes nothing" proof
would be lost. Reuses the Silver MERGE executor so counts are read the same way everywhere.
"""

from __future__ import annotations

from pyspark.sql import DataFrame, SparkSession

from vulnpulse.silver.merge import _merge_counts

AUDIT_COLUMNS = ("batch_id", "load_timestamp")


def changed_condition(columns: list[str], *, exclude: tuple[str, ...] = AUDIT_COLUMNS) -> str:
    """SQL predicate that is true when any non-audit, non-key column differs (null-safe)."""
    compared = [c for c in columns if c not in exclude]
    if not compared:
        return "false"
    return "NOT (" + " AND ".join(f"s.{c} <=> t.{c}" for c in compared) + ")"


def merge_gold(
    spark: SparkSession,
    source: DataFrame,
    target_fqn: str,
    *,
    keys: list[str],
    view_name: str = "_gold_merge_source",
) -> dict[str, int]:
    """Upsert ``source`` into ``target_fqn`` on ``keys``; update only when business columns changed.

    Returns ``{"inserted": n, "updated": n}``.
    """
    business = [c for c in source.columns if c not in keys]
    source.createOrReplaceTempView(view_name)
    on = " AND ".join(f"t.{k} = s.{k}" for k in keys)
    result = spark.sql(
        f"""
        MERGE INTO {target_fqn} AS t
        USING {view_name} AS s
        ON {on}
        WHEN MATCHED AND {changed_condition(business)} THEN UPDATE SET *
        WHEN NOT MATCHED THEN INSERT *
        """
    )
    return _merge_counts(spark, result, target_fqn)
