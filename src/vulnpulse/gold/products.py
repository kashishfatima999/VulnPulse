"""dim_vendor_product and fact_cve_product: the product arm of the star (answers Q2).

    silver_affected_product (CVE x CPE criterion, vulnerable = true only)
            │
            ├──► dim_vendor_product   one row per vendor/product, key = vendor_product_key_expr
            └──► fact_cve_product     one row per CVE x vendor/product, joined to silver_cve for the
                                      published date and severity, and to silver_kev for is_exploited

Only ``vulnerable = true`` CPE matches count: ``vulnerable = false`` entries are the platform a
vulnerable product runs on (e.g. "on Windows"), not an affected product. Several criteria of one
CVE that differ only by version collapse into one vendor/product row.

Pure builders (DataFrame in, DataFrame out); the notebook does the MERGE with ``merge_gold``.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pyspark.sql import Column, DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import TimestampType

from vulnpulse.gold.ddl import DIM_VENDOR_PRODUCT_SCHEMA, FACT_CVE_PRODUCT_SCHEMA
from vulnpulse.gold.keys import date_key_expr, severity_key_expr, vendor_product_key_expr

DIM_VENDOR_PRODUCT_COLUMNS = [f.name for f in DIM_VENDOR_PRODUCT_SCHEMA.fields]
FACT_CVE_PRODUCT_COLUMNS = [f.name for f in FACT_CVE_PRODUCT_SCHEMA.fields]
DIM_VENDOR_PRODUCT_KEYS = ["vendor_product_key"]
FACT_CVE_PRODUCT_KEYS = ["cve_id", "vendor_product_key"]


def vulnerable_products(silver_affected_product: DataFrame) -> DataFrame:
    """Vulnerable rows with a concrete vendor and product, plus their surrogate key."""
    return silver_affected_product.where(
        F.coalesce(F.col("vulnerable"), F.lit(False))
        & F.col("vendor").isNotNull()
        & F.col("product").isNotNull()
    ).withColumn("vendor_product_key", vendor_product_key_expr(F.col("vendor"), F.col("product")))


def cve_attributes(silver_cve: DataFrame, silver_kev: DataFrame) -> DataFrame:
    """Per-CVE columns every bridge fact repeats: date key, severity key, score, is_exploited.

    Derived with the shared key expressions, so they always equal the values in fact_cve.
    """
    kev = silver_kev.select(F.col("cve_id").alias("_kev_cve_id")).distinct()
    cve = silver_cve.select(
        "cve_id",
        date_key_expr(F.col("published_at")).alias("published_date_key"),
        severity_key_expr(F.col("cvss_v3_severity"), F.col("cvss_v3_score")).alias("severity_key"),
        F.col("cvss_v3_score"),
    )
    return (
        cve.join(kev, cve["cve_id"] == kev["_kev_cve_id"], "left")
        .withColumn("is_exploited", F.col("_kev_cve_id").isNotNull().cast("int"))
        .drop("_kev_cve_id")
        .where(F.col("published_date_key").isNotNull())
    )


def build_dim_vendor_product(
    silver_affected_product: DataFrame, *, batch_id: str, load_timestamp: datetime
) -> DataFrame:
    """One row per vendor/product key. Names are lower-cased and trimmed, as in the key."""
    vp = vulnerable_products(silver_affected_product)
    return (
        vp.groupBy("vendor_product_key")
        .agg(
            F.min(F.lower(F.trim("vendor"))).alias("vendor"),
            F.min(F.lower(F.trim("product"))).alias("product"),
            F.min("part").alias("part"),
        )
        .select(
            "vendor_product_key",
            "vendor",
            "product",
            "part",
            F.lit(batch_id).alias("batch_id"),
            _ts(load_timestamp).alias("load_timestamp"),
        )
        .select(*DIM_VENDOR_PRODUCT_COLUMNS)
    )


def build_fact_cve_product(
    silver_affected_product: DataFrame,
    silver_cve: DataFrame,
    silver_kev: DataFrame,
    *,
    batch_id: str,
    load_timestamp: datetime,
) -> DataFrame:
    """One row per CVE x vendor/product. CVEs missing from ``silver_cve`` are left out."""
    pairs = vulnerable_products(silver_affected_product).select(*FACT_CVE_PRODUCT_KEYS).distinct()
    return _bridge(pairs, cve_attributes(silver_cve, silver_kev), batch_id, load_timestamp).select(
        *FACT_CVE_PRODUCT_COLUMNS
    )


def _bridge(pairs: DataFrame, attrs: DataFrame, batch_id: str, load_timestamp: datetime):
    return pairs.join(attrs, "cve_id", "inner").select(
        "*",
        F.lit(batch_id).alias("batch_id"),
        _ts(load_timestamp).alias("load_timestamp"),
    )


def _ts(ts: datetime) -> Column:
    naive = ts if ts.tzinfo is None else ts.astimezone(timezone.utc).replace(tzinfo=None)
    return F.lit(naive).cast(TimestampType())
