"""Bronze-to-Silver transformation for NVD CVE records.

Pure functions: DataFrame in, DataFrame out. No table reads or writes here.

Top-level scalars (id, dates, status, sourceIdentifier) are lifted with ``get_json_object`` so a
type change in one nested field cannot null the whole record. Nested arrays (descriptions,
metrics) are parsed with the explicit ``NVD_CVE_SCHEMA``. Every cast uses a ``try_`` function, so
a bad value becomes NULL (and is caught by the quality rules) instead of failing the batch.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pyspark.sql import Column, DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import TimestampType

from vulnpulse.schemas.nvd import NVD_CVE_KNOWN_KEYS, NVD_CVE_SCHEMA

# NVD emits "2026-09-24T15:38:04.713" (no zone, UTC). Accept the form without millis too.
NVD_TS_FORMATS = ("yyyy-MM-dd'T'HH:mm:ss.SSS", "yyyy-MM-dd'T'HH:mm:ss")

# Columns written to silver_cve, in table order.
SILVER_CVE_COLUMNS = [
    "cve_id",
    "published_at",
    "last_modified_at",
    "vuln_status",
    "description_en",
    "cvss_v3_score",
    "cvss_v3_severity",
    "cvss_vector",
    "has_source_identifier",
    "payload_sha256",
    "batch_id",
    "load_timestamp",
]


def parse_nvd_ts(col: Column) -> Column:
    """String to UTC timestamp; NULL (not an error) when no format matches."""
    return F.coalesce(*[F.try_to_timestamp(col, F.lit(fmt)) for fmt in NVD_TS_FORMATS])


def _json_str(path: str) -> Column:
    return F.get_json_object(F.col("raw_json"), path)


def _primary_metric(metrics: Column) -> Column:
    """The NVD 'Primary' entry of a CVSS metric array, else its first entry, else NULL."""
    primary = F.filter(metrics, lambda m: m["type"] == F.lit("Primary"))
    return F.coalesce(F.try_element_at(primary, F.lit(1)), F.try_element_at(metrics, F.lit(1)))


def transform_nvd(bronze: DataFrame, *, load_timestamp: datetime) -> DataFrame:
    """Bronze NVD rows to Silver-shaped rows.

    Output: the ``SILVER_CVE_COLUMNS`` plus two helper columns the quality step needs and the
    MERGE drops: ``raw_json`` (kept for quarantine) and ``unknown_keys`` (schema drift: top-level
    source keys the typed schema does not know about).
    """
    cve = F.from_json(F.col("raw_json"), NVD_CVE_SCHEMA)
    metric = F.coalesce(
        _primary_metric(cve["metrics"]["cvssMetricV31"]),
        _primary_metric(cve["metrics"]["cvssMetricV30"]),
    )
    # A stringified score ("9.8") still casts; the typed path covers the normal case.
    score_fallback = F.coalesce(
        _json_str("$.metrics.cvssMetricV31[0].cvssData.baseScore"),
        _json_str("$.metrics.cvssMetricV30[0].cvssData.baseScore"),
    )
    english = F.filter(cve["descriptions"], lambda d: d["lang"] == F.lit("en"))
    known_keys = F.array(*[F.lit(k) for k in sorted(NVD_CVE_KNOWN_KEYS)])

    return bronze.select(
        F.trim(F.col("cve_id")).alias("cve_id"),
        parse_nvd_ts(_json_str("$.published")).alias("published_at"),
        parse_nvd_ts(_json_str("$.lastModified")).alias("last_modified_at"),
        _json_str("$.vulnStatus").alias("vuln_status"),
        F.try_element_at(english, F.lit(1))["value"].alias("description_en"),
        metric["cvssData"]["baseScore"].alias("_typed_score"),
        score_fallback.alias("_raw_score"),
        F.upper(metric["cvssData"]["baseSeverity"]).alias("cvss_v3_severity"),
        metric["cvssData"]["vectorString"].alias("cvss_vector"),
        # PII rule: never keep sourceIdentifier, only whether it was present.
        _json_str("$.sourceIdentifier").isNotNull().alias("has_source_identifier"),
        F.col("payload_sha256"),
        F.col("batch_id"),
        F.lit(_naive_utc(load_timestamp)).cast(TimestampType()).alias("load_timestamp"),
        F.col("raw_json"),
        F.array_except(F.json_object_keys(F.col("raw_json")), known_keys).alias("unknown_keys"),
    ).select(
        "cve_id",
        "published_at",
        "last_modified_at",
        "vuln_status",
        "description_en",
        F.coalesce(F.col("_typed_score"), F.expr("try_cast(_raw_score AS double)")).alias(
            "cvss_v3_score"
        ),
        "cvss_v3_severity",
        "cvss_vector",
        "has_source_identifier",
        "payload_sha256",
        "batch_id",
        "load_timestamp",
        "raw_json",
        "unknown_keys",
    )


def _naive_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts
    return ts.astimezone(timezone.utc).replace(tzinfo=None)
