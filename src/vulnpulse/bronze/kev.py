"""Raw-to-Bronze for the CISA Known Exploited Vulnerabilities catalog.

The KEV feed is a single JSON document of about 1,700 entries. There is no incremental API, so
every run is a FULL snapshot: download the catalog, keep every entry verbatim, tag it with the
catalog version. Bronze grain: one row per entry per batch.

How this differs from NVD (``bronze/nvd.py``):
    * NVD has a paged API with ``lastModified`` filters, so NVD supports INCREMENTAL and BACKFILL
      windows and a watermark. KEV has none of that: CISA publishes one file, we take the whole
      file every time. No watermark is kept for KEV.
    * Because each run is a full snapshot, two consecutive runs mostly contain the same entries.
      That is fine: Bronze is append-only and keyed by (cve_id, batch_id), so each snapshot is
      kept side by side. Silver's MERGE collapses them to the latest version per CVE.
    * ``catalog_version`` (e.g. ``2026.10.16``) is CISA's own version stamp for the snapshot and
      is the natural "which copy is newer" signal for Silver.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import StringType, StructField, StructType, TimestampType

# fetch_with_retry is shared with NVD: same backoff (5, 10, 20, 40 s) on 429/5xx/timeouts.
from vulnpulse.ingestion.nvd_api import FetchJson, default_fetch_json, fetch_with_retry

# The explicit envelope schema: catalogVersion, dateReleased, count, vulnerabilities (array of
# typed records). Reading with a declared schema (instead of letting Spark infer it) means a
# malformed or non-JSON file yields NULLs and zero rows rather than a surprise schema.
from vulnpulse.schemas.kev import KEV_CATALOG_RAW_SCHEMA

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
BRONZE_KEV_TABLE = "bronze_cisa_raw"

# Bronze table layout. Same shape as bronze_nvd so the two Bronze tables are read the same way.
# Primary key: (cve_id, batch_id). The same CVE appears once per snapshot, never twice in one.
#
#   cve_id           business key, pulled out of raw_json so Silver can join without parsing
#   catalog_version  CISA's version stamp for this snapshot (from the file header)
#   date_released    CISA's release timestamp for this snapshot (from the file header)
#   raw_json         the entry exactly as CISA sent it; nothing parsed, nothing dropped
#   payload_sha256   fingerprint of raw_json: identical re-sends vs real changes in 64 chars
#   source_uri       where it came from (URL or volume path), for provenance
#   load_type        always FULL for KEV
#   batch_id         the run that wrote the row; links to pipeline_execution_logs
#   load_timestamp   when we loaded it (UTC), distinct from when CISA released it
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
    """Download the live catalog to ``out_path`` and return the path.

    Runs on the laptop via ``scripts/fetch_kev.py`` (Databricks Free Edition has no outbound
    internet). ``fetch_json`` is injectable so unit tests can supply a fake HTTP call and never
    touch the network.
    """
    # One request, with retry/backoff; the whole catalog comes back as one JSON object.
    payload = fetch_with_retry(url, fetch_json=fetch_json)
    path = Path(out_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    # Written back out as JSON unchanged: the landing file is the verbatim source copy.
    path.write_text(json.dumps(payload), encoding="utf-8")
    return str(path)


def read_catalog(spark: SparkSession, path: str) -> DataFrame:
    """One Spark row for the whole file: the envelope (version, date, count, vulnerabilities[])."""
    # multiLine=True because the catalog is one pretty-printed JSON document, not one object per
    # line (which is Spark's default JSON expectation).
    return spark.read.schema(KEV_CATALOG_RAW_SCHEMA).option("multiLine", True).json(path)


def explode_entries(catalog: DataFrame) -> DataFrame:
    """Turn the single envelope row into one row per KEV entry.

    The header fields (catalogVersion, dateReleased) are copied onto every entry so each Bronze
    row carries the version of the snapshot it belongs to. ``explode`` unpacks the
    ``vulnerabilities`` array: 1 row in -> ~1,700 rows out.
    """
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
    """Shape exploded entries into the Bronze layout: verbatim payload + provenance columns.

    Pure function: no I/O, so it is unit-tested on a local Spark session.
    """
    # Spark expects naive timestamps and treats them as UTC (session timezone is set to UTC in
    # the notebook). Converting here keeps load_timestamp correct regardless of the caller's tz.
    ts = _as_naive_utc(load_timestamp)
    return entries.select(
        # Only the key is extracted from the JSON; everything else stays inside raw_json.
        F.get_json_object("raw_json", "$.cveID").alias("cve_id"),
        F.col("catalog_version"),
        F.col("date_released"),
        F.col("raw_json"),
        # SHA-256 over the verbatim text: same entry in two snapshots -> same hash.
        F.sha2(F.col("raw_json"), 256).alias("payload_sha256"),
        # Provenance: constant per run, stamped on every row (contract: every row traces to a run).
        F.lit(source_uri).alias("source_uri"),
        F.lit(load_type).alias("load_type"),
        F.lit(batch_id).alias("batch_id"),
        F.lit(ts).cast(TimestampType()).alias("load_timestamp"),
    )


def ensure_table(spark: SparkSession, table_fqn: str) -> None:
    """Create the Delta table from BRONZE_KEV_SCHEMA if missing. Safe to call every run."""
    # The DDL is generated from the same StructType the DataFrame uses, so table and data can
    # never drift apart (one definition, two uses).
    columns = ", ".join(f"{f.name} {f.dataType.simpleString()}" for f in BRONZE_KEV_SCHEMA.fields)
    spark.sql(
        f"CREATE TABLE IF NOT EXISTS {table_fqn} ({columns}) USING DELTA "
        "COMMENT 'Raw CISA KEV entries, one row per entry per snapshot, verbatim JSON in raw_json'"
    )


def append(df: DataFrame, table_fqn: str) -> None:
    """Append-only write. Bronze never updates or deletes; history is kept, Silver dedups."""
    df.write.format("delta").mode("append").saveAsTable(table_fqn)


def _as_naive_utc(ts: datetime) -> datetime:
    """Aware datetime (any zone) -> naive UTC. Naive input is assumed to already be UTC."""
    if ts.tzinfo is None:
        return ts
    return ts.astimezone(timezone.utc).replace(tzinfo=None)
