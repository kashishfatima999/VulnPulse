"""Raw-to-Bronze for NVD CVE payloads.

Bronze grain: **one row per CVE record** as it appeared in the source page or feed file. The
record itself is kept verbatim in ``raw_json``; a few fields are lifted out next to it so that
later layers can filter and the watermark can be computed without parsing the whole payload.

Pure transformation functions (``read_nvd_pages``, ``explode_cves``, ``to_bronze``) take and
return DataFrames and are unit-tested locally. Table I/O (``ensure_table``, ``append``) is thin
and runs only in Databricks.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import StringType, StructField, StructType, TimestampType

from vulnpulse.schemas.nvd import NVD_PAGE_RAW_SCHEMA

BRONZE_NVD_TABLE = "bronze_nvd_raw"

# Primary key: (cve_id, batch_id). The same CVE can legitimately appear in many batches.
BRONZE_NVD_SCHEMA = StructType(
    [
        StructField("cve_id", StringType(), nullable=False),
        StructField("source_last_modified", StringType()),
        StructField("raw_json", StringType(), nullable=False),
        StructField("payload_sha256", StringType(), nullable=False),
        StructField("source_uri", StringType(), nullable=False),
        StructField("load_type", StringType(), nullable=False),
        StructField("batch_id", StringType(), nullable=False),
        StructField("load_timestamp", TimestampType(), nullable=False),
    ]
)


def read_nvd_pages(spark: SparkSession, path: str) -> DataFrame:
    """Read one or more NVD page/feed files (plain or gzip) with the explicit envelope schema."""
    return spark.read.schema(NVD_PAGE_RAW_SCHEMA).option("multiLine", True).json(path)


def explode_cves(pages: DataFrame) -> DataFrame:
    """One row per CVE with the verbatim record in ``raw_json``."""
    return pages.select(F.explode("vulnerabilities").alias("v")).select(
        F.col("v.cve").alias("raw_json")
    )


def to_bronze(
    raw: DataFrame,
    *,
    source_uri: str,
    load_type: str,
    batch_id: str,
    load_timestamp: datetime,
) -> DataFrame:
    """Attach ingestion metadata to raw CVE strings, producing rows in ``BRONZE_NVD_SCHEMA`` order."""
    ts = _as_naive_utc(load_timestamp)
    return raw.select(
        F.get_json_object("raw_json", "$.id").alias("cve_id"),
        F.get_json_object("raw_json", "$.lastModified").alias("source_last_modified"),
        F.col("raw_json"),
        F.sha2(F.col("raw_json"), 256).alias("payload_sha256"),
        F.lit(source_uri).alias("source_uri"),
        F.lit(load_type).alias("load_type"),
        F.lit(batch_id).alias("batch_id"),
        F.lit(ts).cast(TimestampType()).alias("load_timestamp"),
    )


def ensure_table(spark: SparkSession, table_fqn: str) -> None:
    """Create the Bronze table with the exact declared schema if it does not exist yet."""
    columns = ", ".join(f"{f.name} {f.dataType.simpleString()}" for f in BRONZE_NVD_SCHEMA.fields)
    spark.sql(
        f"CREATE TABLE IF NOT EXISTS {table_fqn} ({columns}) USING DELTA "
        "COMMENT 'Raw NVD CVE records, one row per record per batch, verbatim JSON in raw_json'"
    )


def append(df: DataFrame, table_fqn: str) -> None:
    """Append-only write. Bronze never updates or deletes."""
    df.write.format("delta").mode("append").saveAsTable(table_fqn)


def _as_naive_utc(ts: datetime) -> datetime:
    """Spark stores timestamps as UTC instants; hand it a naive UTC datetime to avoid zone guessing."""
    if ts.tzinfo is None:
        return ts
    return ts.astimezone(timezone.utc).replace(tzinfo=None)
