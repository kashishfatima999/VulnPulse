"""Silver data-quality rules and the quarantine split.

A record that cannot be made to conform is not dropped and does not abort the batch: it is
routed to ``silver_quarantine`` with the first rule it broke as ``reason`` (contract rule 9).
Rules are (condition, reason) pairs evaluated in order; a condition is True when the row is BAD.
"""

from __future__ import annotations

from pyspark.sql import Column, DataFrame
from pyspark.sql import functions as F

CVE_ID_PATTERN = r"^CVE-\d{4}-\d{4,}$"

REASON_MISSING_ID = "missing_cve_id"
REASON_BAD_ID = "invalid_cve_id_format"
REASON_BAD_PUBLISHED = "unparseable_published"
REASON_BAD_LAST_MODIFIED = "unparseable_last_modified"
REASON_BAD_DATE_ADDED = "unparseable_date_added"

QUARANTINE_COLUMNS = [
    "source_table",
    "cve_id",
    "reason",
    "raw_json",
    "payload_sha256",
    "batch_id",
    "load_timestamp",
]


def _id_rules() -> list[tuple[Column, str]]:
    cve_id = F.col("cve_id")
    return [
        (cve_id.isNull() | (F.trim(cve_id) == ""), REASON_MISSING_ID),
        (~cve_id.rlike(CVE_ID_PATTERN), REASON_BAD_ID),
    ]


def nvd_rules() -> list[tuple[Column, str]]:
    return _id_rules() + [
        (F.col("published_at").isNull(), REASON_BAD_PUBLISHED),
        (F.col("last_modified_at").isNull(), REASON_BAD_LAST_MODIFIED),
    ]


def kev_rules() -> list[tuple[Column, str]]:
    return _id_rules() + [(F.col("date_added").isNull(), REASON_BAD_DATE_ADDED)]


def split_valid_invalid(
    df: DataFrame, rules: list[tuple[Column, str]], *, source_table: str
) -> tuple[DataFrame, DataFrame]:
    """Return ``(valid, quarantine)``. ``quarantine`` is in ``QUARANTINE_COLUMNS`` order."""
    reason = F.lit(None).cast("string")
    for condition, label in reversed(rules):
        reason = F.when(condition, F.lit(label)).otherwise(reason)
    tagged = df.withColumn("_reason", reason)

    valid = tagged.where(F.col("_reason").isNull()).drop("_reason")
    quarantine = tagged.where(F.col("_reason").isNotNull()).select(
        F.lit(source_table).alias("source_table"),
        F.col("cve_id"),
        F.col("_reason").alias("reason"),
        F.col("raw_json"),
        F.col("payload_sha256"),
        F.col("batch_id"),
        F.col("load_timestamp"),
    )
    return valid, quarantine