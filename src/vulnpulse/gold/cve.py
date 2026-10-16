"""dim_cve and fact_cve: the CVE-grain core of the star.

Pure builders (DataFrame in, DataFrame out) so they are unit-tested locally; the notebook does the
MERGE. Inputs are Silver tables, never Bronze (contract rule 21).

    silver_cve  (one row per CVE)   +   silver_kev (one row per exploited CVE)
            │ left join on cve_id
            ├──► dim_cve   descriptive attributes + KEV attributes, is_in_kev
            └──► fact_cve  date keys, severity key, score, flags, days_to_kev, counts
"""

from __future__ import annotations

from datetime import datetime, timezone

from pyspark.sql import DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import TimestampType

from vulnpulse.gold.ddl import DIM_CVE_SCHEMA, FACT_CVE_SCHEMA
from vulnpulse.gold.keys import date_key_expr, severity_key_expr

DIM_CVE_COLUMNS = [f.name for f in DIM_CVE_SCHEMA.fields]
FACT_CVE_COLUMNS = [f.name for f in FACT_CVE_SCHEMA.fields]


def _joined(silver_cve: DataFrame, silver_kev: DataFrame) -> DataFrame:
    kev = silver_kev.select(
        F.col("cve_id").alias("kev_cve_id"),
        F.col("vendor_project").alias("kev_vendor_project"),
        F.col("product").alias("kev_product"),
        F.col("vulnerability_name").alias("kev_vulnerability_name"),
        F.col("date_added").alias("kev_date_added"),
        F.col("due_date").alias("kev_due_date"),
        F.col("known_ransomware_campaign_use"),
        F.col("required_action").alias("kev_required_action"),
    )
    return silver_cve.join(kev, silver_cve["cve_id"] == kev["kev_cve_id"], "left")


def build_dim_cve(
    silver_cve: DataFrame, silver_kev: DataFrame, *, batch_id: str, load_timestamp: datetime
) -> DataFrame:
    j = _joined(silver_cve, silver_kev)
    return j.select(
        F.col("cve_id"),
        F.col("description_en"),
        F.col("vuln_status"),
        F.col("cvss_vector"),
        F.col("has_source_identifier"),
        F.col("kev_cve_id").isNotNull().alias("is_in_kev"),
        F.col("kev_vendor_project"),
        F.col("kev_product"),
        F.col("kev_vulnerability_name"),
        F.col("known_ransomware_campaign_use"),
        F.col("kev_required_action"),
        F.col("kev_due_date"),
        F.lit(batch_id).alias("batch_id"),
        _ts(load_timestamp).alias("load_timestamp"),
    ).select(*DIM_CVE_COLUMNS)


def build_fact_cve(
    silver_cve: DataFrame,
    silver_kev: DataFrame,
    *,
    batch_id: str,
    load_timestamp: datetime,
    product_counts: DataFrame | None = None,
    cwe_counts: DataFrame | None = None,
) -> DataFrame:
    """One row per CVE.

    ``product_counts`` / ``cwe_counts`` are optional ``(cve_id, n)`` DataFrames from Zahra's Silver
    tables; when absent the counts are NULL rather than 0, so "unknown" is not confused with "none".
    """
    j = _joined(silver_cve, silver_kev)
    published = F.to_date("published_at")
    exploited = F.col("kev_cve_id").isNotNull()

    fact = j.select(
        F.col("cve_id"),
        date_key_expr(F.col("published_at")).alias("published_date_key"),
        date_key_expr(F.col("last_modified_at")).alias("last_modified_date_key"),
        date_key_expr(F.col("kev_date_added")).alias("kev_added_date_key"),
        date_key_expr(F.col("kev_due_date")).alias("kev_due_date_key"),
        severity_key_expr(F.col("cvss_v3_severity"), F.col("cvss_v3_score")).alias("severity_key"),
        F.col("cvss_v3_score"),
        exploited.cast("int").alias("is_exploited"),
        (exploited & (F.lower(F.col("known_ransomware_campaign_use")) == "known"))
        .cast("int")
        .alias("is_ransomware"),
        F.when(exploited, F.datediff(F.col("kev_date_added"), published))
        .cast("int")
        .alias("days_to_kev"),
        F.lit(1).cast("int").alias("cve_count"),
        F.lit(batch_id).alias("batch_id"),
        _ts(load_timestamp).alias("load_timestamp"),
    )

    fact = _attach_count(fact, product_counts, "product_count")
    fact = _attach_count(fact, cwe_counts, "cwe_count")
    return fact.select(*FACT_CVE_COLUMNS)


def count_per_cve(df: DataFrame) -> DataFrame:
    """``(cve_id, n)`` from any Silver child table keyed by cve_id (products, CWEs)."""
    return df.groupBy("cve_id").agg(F.count("*").cast("int").alias("n"))


def _attach_count(fact: DataFrame, counts: DataFrame | None, name: str) -> DataFrame:
    if counts is None:
        return fact.withColumn(name, F.lit(None).cast("int"))
    c = counts.select(F.col("cve_id").alias("_cid"), F.col("n").alias(name))
    return fact.join(c, fact["cve_id"] == c["_cid"], "left").drop("_cid")


def _ts(ts: datetime):
    naive = ts if ts.tzinfo is None else ts.astimezone(timezone.utc).replace(tzinfo=None)
    return F.lit(naive).cast(TimestampType())
