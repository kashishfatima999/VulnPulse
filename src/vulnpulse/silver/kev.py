"""Bronze-to-Silver transformation for CISA KEV entries.

Same contract as the NVD transform: pure, DataFrame in and out, every cast is a ``try_`` cast so
a bad value becomes NULL and is quarantined by the quality rules instead of failing the batch.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pyspark.sql import DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import TimestampType

from vulnpulse.schemas.kev import KEV_KNOWN_KEYS, KEV_RECORD_SCHEMA

# Columns written to silver_kev, in table order.
SILVER_KEV_COLUMNS = [
    "cve_id",
    "vendor_project",
    "product",
    "vulnerability_name",
    "date_added",
    "due_date",
    "known_ransomware_campaign_use",
    "required_action",
    "catalog_version",
    "payload_sha256",
    "batch_id",
    "load_timestamp",
]

# Dedup order for KEV (no modification timestamp): newest catalog, then newest batch.
KEV_DEDUP_ORDER = ["catalog_version", "batch_id", "payload_sha256"]


def transform_kev(bronze: DataFrame, *, load_timestamp: datetime) -> DataFrame:
    """Bronze KEV rows to Silver-shaped rows, plus ``raw_json`` and ``unknown_keys`` helpers."""
    kev = F.from_json(F.col("raw_json"), KEV_RECORD_SCHEMA)
    known_keys = F.array(*[F.lit(k) for k in sorted(KEV_KNOWN_KEYS)])
    return bronze.select(
        F.trim(F.col("cve_id")).alias("cve_id"),
        kev["vendorProject"].alias("vendor_project"),
        kev["product"].alias("product"),
        kev["vulnerabilityName"].alias("vulnerability_name"),
        F.expr("try_to_date(get_json_object(raw_json, '$.dateAdded'), 'yyyy-MM-dd')").alias(
            "date_added"
        ),
        F.expr("try_to_date(get_json_object(raw_json, '$.dueDate'), 'yyyy-MM-dd')").alias(
            "due_date"
        ),
        kev["knownRansomwareCampaignUse"].alias("known_ransomware_campaign_use"),
        kev["requiredAction"].alias("required_action"),
        F.col("catalog_version"),
        F.col("payload_sha256"),
        F.col("batch_id"),
        F.lit(_naive_utc(load_timestamp)).cast(TimestampType()).alias("load_timestamp"),
        F.col("raw_json"),
        F.array_except(F.json_object_keys(F.col("raw_json")), known_keys).alias("unknown_keys"),
    )


def _naive_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts
    return ts.astimezone(timezone.utc).replace(tzinfo=None)
