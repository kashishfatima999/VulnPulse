"""dim_cwe and fact_cve_cwe: the weakness arm of the star (answers Q3).

    silver_cwe (CVE x CWE id)
            │
            ├──► dim_cwe        one row per weakness, key = cwe_key_expr ('CWE-79' -> 79,
            │                   'NVD-CWE-noinfo' -> -1, 'NVD-CWE-Other' -> -2)
            └──► fact_cve_cwe   one row per CVE x weakness, with the same date key, severity key,
                                score and is_exploited as fact_cve

Pure builders (DataFrame in, DataFrame out); the notebook does the MERGE with ``merge_gold``.
"""

from __future__ import annotations

from datetime import datetime

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from vulnpulse.gold.ddl import DIM_CWE_SCHEMA, FACT_CVE_CWE_SCHEMA
from vulnpulse.gold.keys import cwe_category_expr, cwe_key_expr
from vulnpulse.gold.products import _bridge, _ts, cve_attributes

DIM_CWE_COLUMNS = [f.name for f in DIM_CWE_SCHEMA.fields]
FACT_CVE_CWE_COLUMNS = [f.name for f in FACT_CVE_CWE_SCHEMA.fields]
DIM_CWE_KEYS = ["cwe_key"]
FACT_CVE_CWE_KEYS = ["cve_id", "cwe_key"]


def keyed_cwes(silver_cwe: DataFrame) -> DataFrame:
    """Silver CWE rows with their integer key; ids the key rule cannot map are left out."""
    return silver_cwe.withColumn("cwe_key", cwe_key_expr(F.col("cwe_id"))).where(
        F.col("cwe_key").isNotNull()
    )


def build_dim_cwe(silver_cwe: DataFrame, *, batch_id: str, load_timestamp: datetime) -> DataFrame:
    return (
        keyed_cwes(silver_cwe)
        .groupBy("cwe_key")
        .agg(F.min("cwe_id").alias("cwe_id"))
        .select(
            "cwe_key",
            "cwe_id",
            cwe_category_expr(F.col("cwe_id")).alias("cwe_category"),
            F.lit(batch_id).alias("batch_id"),
            _ts(load_timestamp).alias("load_timestamp"),
        )
        .select(*DIM_CWE_COLUMNS)
    )


def build_fact_cve_cwe(
    silver_cwe: DataFrame,
    silver_cve: DataFrame,
    silver_kev: DataFrame,
    *,
    batch_id: str,
    load_timestamp: datetime,
) -> DataFrame:
    """One row per CVE x CWE. CVEs missing from ``silver_cve`` are left out."""
    pairs = keyed_cwes(silver_cwe).select(*FACT_CVE_CWE_KEYS).distinct()
    return _bridge(pairs, cve_attributes(silver_cve, silver_kev), batch_id, load_timestamp).select(
        *FACT_CVE_CWE_COLUMNS
    )
