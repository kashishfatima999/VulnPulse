"""Deterministic key expressions shared by every Gold builder.

Both halves of the star (Kashish's dim_cve/fact_cve, Zahra's product and CWE arms) must derive
keys identically, otherwise facts will not join to dimensions. Import from here; never re-derive.
"""

from __future__ import annotations

from pyspark.sql import Column
from pyspark.sql import functions as F

# dim_severity keys. Order matters for sort_order and for the band lookup below.
SEVERITY_ROWS: list[tuple[int, str, float | None, float | None, int, str]] = [
    (1, "CRITICAL", 9.0, 10.0, 1, "CVSS v3 base score 9.0-10.0"),
    (2, "HIGH", 7.0, 8.9, 2, "CVSS v3 base score 7.0-8.9"),
    (3, "MEDIUM", 4.0, 6.9, 3, "CVSS v3 base score 4.0-6.9"),
    (4, "LOW", 0.1, 3.9, 4, "CVSS v3 base score 0.1-3.9"),
    (5, "NONE", 0.0, 0.0, 5, "CVSS v3 base score 0.0"),
    (6, "UNKNOWN", None, None, 6, "No CVSS v3 metric published (v2-only or awaiting analysis)"),
]
SEVERITY_KEY_UNKNOWN = 6
SEVERITY_KEY_BY_LABEL = {label: key for key, label, *_ in SEVERITY_ROWS}

CWE_KEY_NOINFO = -1
CWE_KEY_OTHER = -2


def date_key_expr(ts: Column) -> Column:
    """TIMESTAMP or DATE column -> INT yyyymmdd; NULL stays NULL."""
    d = F.to_date(ts)
    return (F.year(d) * 10000 + F.month(d) * 100 + F.dayofmonth(d)).cast("int")


def severity_key_expr(severity: Column, score: Column) -> Column:
    """Prefer the label NVD published; fall back to the score band; else UNKNOWN (6)."""
    by_label = F.when(F.upper(severity) == "CRITICAL", 1)
    for key, label, *_ in SEVERITY_ROWS[1:5]:
        by_label = by_label.when(F.upper(severity) == label, key)
    by_score = (
        F.when(score >= 9.0, 1)
        .when(score >= 7.0, 2)
        .when(score >= 4.0, 3)
        .when(score > 0.0, 4)
        .when(score == 0.0, 5)
    )
    return F.coalesce(by_label, by_score, F.lit(SEVERITY_KEY_UNKNOWN)).cast("int")


def vendor_product_key_expr(vendor: Column, product: Column) -> Column:
    """Stable 64-bit surrogate for a vendor/product pair (lower-cased, trimmed)."""
    return F.xxhash64(F.lower(F.trim(vendor)), F.lit("|"), F.lower(F.trim(product)))


def cwe_key_expr(cwe_id: Column) -> Column:
    """'CWE-79' -> 79; 'NVD-CWE-noinfo' -> -1; 'NVD-CWE-Other' -> -2; anything else NULL."""
    digits = F.regexp_extract(cwe_id, r"^CWE-(\d+)$", 1)
    return (
        F.when(cwe_id == "NVD-CWE-noinfo", F.lit(CWE_KEY_NOINFO))
        .when(cwe_id == "NVD-CWE-Other", F.lit(CWE_KEY_OTHER))
        .when(digits != "", digits.cast("int"))
        .cast("int")
    )


def cwe_category_expr(cwe_id: Column) -> Column:
    return (
        F.when(cwe_id == "NVD-CWE-noinfo", F.lit("NVD-CWE-noinfo"))
        .when(cwe_id == "NVD-CWE-Other", F.lit("NVD-CWE-Other"))
        .otherwise(F.lit("CWE"))
    )
