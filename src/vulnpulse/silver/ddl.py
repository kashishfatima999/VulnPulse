"""Silver table definitions and idempotent DDL.

Phase 2 scope: ``silver_cve``, ``silver_kev`` and ``silver_quarantine``. Every row carries
``batch_id`` (the Bronze batch it came from) and ``load_timestamp`` (UTC, when Silver wrote it).
Running ``ensure_tables`` any number of times is safe: everything is ``IF NOT EXISTS``.
"""

from __future__ import annotations

from pyspark.sql import SparkSession
from pyspark.sql.types import (
    BooleanType,
    DateType,
    DoubleType,
    StringType,
    StructField,
    StructType,
    TimestampType,
)

SILVER_CVE_TABLE = "silver_cve"
SILVER_KEV_TABLE = "silver_kev"
SILVER_QUARANTINE_TABLE = "silver_quarantine"

# Primary key: cve_id.
SILVER_CVE_SCHEMA = StructType(
    [
        StructField("cve_id", StringType(), nullable=False),
        StructField("published_at", TimestampType()),
        StructField("last_modified_at", TimestampType()),
        StructField("vuln_status", StringType()),
        StructField("description_en", StringType()),
        StructField("cvss_v3_score", DoubleType()),
        StructField("cvss_v3_severity", StringType()),
        StructField("cvss_vector", StringType()),
        StructField("has_source_identifier", BooleanType()),
        StructField("payload_sha256", StringType()),
        StructField("batch_id", StringType(), nullable=False),
        StructField("load_timestamp", TimestampType(), nullable=False),
    ]
)

# Primary key: cve_id.
SILVER_KEV_SCHEMA = StructType(
    [
        StructField("cve_id", StringType(), nullable=False),
        StructField("vendor_project", StringType()),
        StructField("product", StringType()),
        StructField("vulnerability_name", StringType()),
        StructField("date_added", DateType()),
        StructField("due_date", DateType()),
        StructField("known_ransomware_campaign_use", StringType()),
        StructField("required_action", StringType()),
        StructField("catalog_version", StringType()),
        StructField("payload_sha256", StringType()),
        StructField("batch_id", StringType(), nullable=False),
        StructField("load_timestamp", TimestampType(), nullable=False),
    ]
)

# Primary key: (source_table, batch_id, payload_sha256, reason). cve_id may be null here,
# because a missing id is one of the reasons a record lands in quarantine.
SILVER_QUARANTINE_SCHEMA = StructType(
    [
        StructField("source_table", StringType(), nullable=False),
        StructField("cve_id", StringType()),
        StructField("reason", StringType(), nullable=False),
        StructField("raw_json", StringType()),
        StructField("payload_sha256", StringType(), nullable=False),
        StructField("batch_id", StringType(), nullable=False),
        StructField("load_timestamp", TimestampType(), nullable=False),
    ]
)

_TABLES = {
    SILVER_CVE_TABLE: (SILVER_CVE_SCHEMA, "One row per CVE: typed, deduplicated, PII-sanitised"),
    SILVER_KEV_TABLE: (SILVER_KEV_SCHEMA, "One row per CISA known exploited CVE"),
    SILVER_QUARANTINE_TABLE: (
        SILVER_QUARANTINE_SCHEMA,
        "Bronze records that could not be conformed to Silver, with the reason",
    ),
}


def column_ddl(schema: StructType) -> str:
    """``name type [NOT NULL], ...`` for a CREATE TABLE statement."""
    return ", ".join(
        f"{f.name} {f.dataType.simpleString()}{'' if f.nullable else ' NOT NULL'}"
        for f in schema.fields
    )


def ensure_tables(spark: SparkSession, silver_schema_fqn: str) -> dict[str, str]:
    """Create every Silver table if missing. Returns ``{short name: fully qualified name}``."""
    created = {}
    for name, (schema, comment) in _TABLES.items():
        fqn = f"{silver_schema_fqn}.{name}"
        spark.sql(
            f"CREATE TABLE IF NOT EXISTS {fqn} ({column_ddl(schema)}) USING DELTA "
            f"COMMENT '{comment}'"
        )
        created[name] = fqn
    return created