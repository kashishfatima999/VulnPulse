"""Raw-to-Bronze for NVD CVE payloads.

Bronze grain: **one row per CVE record** as it appeared in the source page or feed file. The
record itself is kept verbatim in ``raw_json``; a few fields are lifted out next to it so that
later layers can filter and the watermark can be computed without parsing the whole payload.

Pure transformation functions (``read_nvd_pages``, ``explode_cves``, ``to_bronze``) take and
return DataFrames and are unit-tested locally. Table I/O (``ensure_table``, ``append``) is thin
and runs only in Databricks.

How this differs from KEV (``bronze/kev.py``):
    * NVD is the INCREMENTAL source. Its API accepts ``lastModStartDate``/``lastModEndDate``, so
      we can ask "what changed since the watermark?" and load only that. KEV has no such filter,
      so KEV is always a FULL snapshot.
    * Because of that, NVD lifts ``source_last_modified`` out of each record. It is the value the
      watermark is computed from (max over the batch) and the value Silver uses to decide which
      version of a CVE is newest. KEV lifts ``catalog_version``/``date_released`` instead, which
      come from the file header, not the record.
    * NVD data arrives as many page files (``page_000.json``, ``page_001.json``, ...) because the
      API returns at most 2,000 records per call. KEV arrives as one file.
    * Everything else (verbatim ``raw_json``, SHA-256, provenance columns, append-only writes)
      is identical by design so Silver can treat both Bronze tables the same way.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import StringType, StructField, StructType, TimestampType

# The explicit envelope schema: resultsPerPage, startIndex, totalResults, format, version,
# timestamp, vulnerabilities[ {cve: STRING} ]. ``cve`` is declared as a STRING on purpose: Spark
# keeps the whole object as text instead of parsing it, so new or changed fields inside a CVE can
# never break Bronze (contract: verbatim capture).
from vulnpulse.schemas.nvd import NVD_PAGE_RAW_SCHEMA

BRONZE_NVD_TABLE = "bronze_nvd_raw"

# Bronze table layout. Same shape as bronze_cisa_raw except for the lifted source columns.
# Primary key: (cve_id, batch_id). The same CVE can legitimately appear in many batches: once per
# time NVD modified it and we fetched it. Bronze keeps every version; Silver picks the newest.
#
#   cve_id                business key, e.g. CVE-2026-12345, lifted from raw_json "$.id"
#   source_last_modified  NVD's own lastModified stamp, lifted from "$.lastModified".
#                         Kept as STRING (verbatim). This is the watermark column: after an
#                         INCREMENTAL load the notebook takes max(source_last_modified) of the
#                         batch and stores it as the new watermark. KEV has no equivalent.
#   raw_json              the CVE object exactly as NVD sent it; nothing parsed, nothing dropped
#   payload_sha256        fingerprint of raw_json: identical re-sends vs real changes in 64 chars
#   source_uri            the first page URL of the window (from the manifest), for provenance
#   load_type             FULL (yearly feed file), INCREMENTAL (window after the watermark) or
#                         BACKFILL (bounded window in the past). KEV only ever has FULL.
#   batch_id              the run that wrote the row; links to pipeline_execution_logs and to the
#                         landing folder name
#   load_timestamp        when we loaded it (UTC), distinct from when NVD modified it
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
    """Read one or more NVD page/feed files (plain or gzip) with the explicit envelope schema.

    ``path`` can be a single file (FULL feed, e.g. ``nvdcve-2.0-2020.json.gz``) or a glob such as
    ``.../page_*.json`` (INCREMENTAL/BACKFILL landing folder). Gzip is decompressed by Spark
    automatically. One Spark row per file = one page envelope.
    """
    # multiLine=True: each page is one pretty-printed JSON document, not one object per line.
    # A non-JSON or malformed file does not match the schema -> NULL envelope -> zero CVE rows
    # after explode. The run then logs "read 0" rather than loading garbage.
    return spark.read.schema(NVD_PAGE_RAW_SCHEMA).option("multiLine", True).json(path)


def explode_cves(pages: DataFrame) -> DataFrame:
    """One row per CVE with the verbatim record in ``raw_json``.

    ``explode`` unpacks the ``vulnerabilities`` array: 1 page row -> up to 2,000 CVE rows.
    Only ``v.cve`` is kept; the page-level counters (startIndex, totalResults) are pagination
    bookkeeping and are already recorded in the manifest.
    """
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
    """Attach ingestion metadata to raw CVE strings, producing rows in ``BRONZE_NVD_SCHEMA`` order.

    Pure function: no I/O, so it is unit-tested on a local Spark session.
    """
    # Spark expects naive timestamps and treats them as UTC (session timezone is set to UTC in
    # the notebook). Converting here keeps load_timestamp correct regardless of the caller's tz.
    ts = _as_naive_utc(load_timestamp)
    return raw.select(
        # Only two values are lifted out of the JSON; everything else stays inside raw_json.
        # get_json_object reads a path from the text without parsing the whole document.
        F.get_json_object("raw_json", "$.id").alias("cve_id"),
        # NVD-only: the source's modification stamp, used for the watermark and Silver's
        # "strictly newer" MERGE condition. KEV's to_bronze lifts catalog_version instead.
        F.get_json_object("raw_json", "$.lastModified").alias("source_last_modified"),
        F.col("raw_json"),
        # SHA-256 over the verbatim text: same record in two batches -> same hash.
        F.sha2(F.col("raw_json"), 256).alias("payload_sha256"),
        # Provenance: constant per run, stamped on every row (contract: every row traces to a run).
        F.lit(source_uri).alias("source_uri"),
        F.lit(load_type).alias("load_type"),
        F.lit(batch_id).alias("batch_id"),
        F.lit(ts).cast(TimestampType()).alias("load_timestamp"),
    )


def ensure_table(spark: SparkSession, table_fqn: str) -> None:
    """Create the Bronze table with the exact declared schema if it does not exist yet."""
    # The DDL is generated from the same StructType the DataFrame uses, so table and data can
    # never drift apart (one definition, two uses). Safe to call every run.
    columns = ", ".join(f"{f.name} {f.dataType.simpleString()}" for f in BRONZE_NVD_SCHEMA.fields)
    spark.sql(
        f"CREATE TABLE IF NOT EXISTS {table_fqn} ({columns}) USING DELTA "
        "COMMENT 'Raw NVD CVE records, one row per record per batch, verbatim JSON in raw_json'"
    )


def append(df: DataFrame, table_fqn: str) -> None:
    """Append-only write. Bronze never updates or deletes.

    This is what makes the 10-minute watermark overlap safe: a CVE re-sent by NVD simply becomes
    a second row with a different batch_id. Silver's MERGE sees an equal last_modified_at and
    does nothing. History is kept, so Silver can always be rebuilt from Bronze.
    """
    df.write.format("delta").mode("append").saveAsTable(table_fqn)


def _as_naive_utc(ts: datetime) -> datetime:
    """Spark stores timestamps as UTC instants; hand it a naive UTC datetime to avoid zone guessing."""
    if ts.tzinfo is None:
        return ts
    return ts.astimezone(timezone.utc).replace(tzinfo=None)
