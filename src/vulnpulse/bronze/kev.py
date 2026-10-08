"""Raw-to-Bronze for the CISA Known Exploited Vulnerabilities catalog.

The KEV feed is a single JSON document of about 1,700 entries. There is no incremental API, so
every run is a FULL snapshot: download the catalog, keep every entry verbatim, tag it with the
catalog version. Bronze grain: one row per entry per batch.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import StringType, StructField, StructType, TimestampType

from vulnpulse.ingestion.nvd_api import FetchJson, default_fetch_json, fetch_with_retry
from vulnpulse.schemas.kev import KEV_CATALOG_RAW_SCHEMA

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
BRONZE_KEV_TABLE = "bronze_cisa_raw"

# Primary key: (cve_id, batch_id).
BRONZE_KEV_SCHEMA = StructType(
    [
        StructField("cve_id", StringType(), nullable=False),
        StructField("catalog_version", StringType()),
        StructField("date_released", StringType()),
        StructField("raw_json", StringType(), nullable=False),
        StructField("payload_sha256", StringType(), nullable=False),
        StructField("source_uri", StringType(), nullable=False),
        StructField("load_type", StringType(), nullable=False),
        StructField("batch_id", StringType(), nullable=False),
        StructField("load_timestamp", TimestampType(), nullable=False),
    ]
)


def download_catalog(
    out_path: str, *, url: str = KEV_URL, fetch_json: FetchJson = default_fetch_json
) -> str:
    """Download the live catalog to ``out_path`` and return the path."""
    payload = fetch_with_retry(url, fetch_json=fetch_json)
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def read_catalog(spark: SparkSession, path: str) -> DataFrame:
    return spark.read.schema(KEV_CATALOG_RAW_SCHEMA).option("multiLine", True).json(path)


def explode_entries(catalog: DataFrame) -> DataFrame:
    return catalog.select(
        F.col("catalogVersion").alias("catalog_version"),
        F.col("dateReleased").alias("date_released"),
        F.explode("vulnerabilities").alias("raw_json"),
    )


def to_bronze(
    entries: DataFrame,
    *,
    source_uri: str,
    load_type: str,
    batch_id: str,
    load_timestamp: datetime,
) -> DataFrame:
    ts = _as_naive_utc(load_timestamp)
    return entries.select(
        F.get_json_object("raw_json", "$.cveID").alias("cve_id"),
        F.col("catalog_version"),
        F.col("date_released"),
        F.col("raw_json"),
        F.sha2(F.col("raw_json"), 256).alias("payload_sha256"),
        F.lit(source_uri).alias("source_uri"),
        F.lit(load_type).alias("load_type"),
        F.lit(batch_id).alias("batch_id"),
        F.lit(ts).cast(TimestampType()).alias("load_timestamp"),
    )


def ensure_table(spark: SparkSession, table_fqn: str) -> None:
    columns = ", ".join(f"{f.name} {f.dataType.simpleString()}" for f in BRONZE_KEV_SCHEMA.fields)
    spark.sql(
        f"CREATE TABLE IF NOT EXISTS {table_fqn} ({columns}) USING DELTA "
        "COMMENT 'Raw CISA KEV entries, one row per entry per snapshot, verbatim JSON in raw_json'"
    )


def append(df: DataFrame, table_fqn: str) -> None:
    df.write.format("delta").mode("append").saveAsTable(table_fqn)


def _as_naive_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts
    return ts.astimezone(timezone.utc).replace(tzinfo=None)
