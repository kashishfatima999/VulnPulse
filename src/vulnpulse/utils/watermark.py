"""High-water mark for incremental loads.

The watermark is the largest source ``lastModified`` value we have successfully landed in Bronze
for a given source. The next INCREMENTAL run asks the API for everything modified after
``watermark - overlap``. The overlap exists because NVD commits records a few minutes after their
``lastModified`` stamp; without it a record could slip between two runs. The duplicates that the
overlap creates are harmless in Bronze (append-only) and removed by Silver's MERGE.

Rules (PROJECT_CONTRACT.md 12 and 13): BACKFILL never moves the watermark, and the watermark is
written only after the batch succeeded. History is kept: every advance is a new row, the current
value is the maximum.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pyspark.sql import SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import StringType, StructField, StructType, TimestampType

WATERMARK_TABLE = "pipeline_watermarks"
SOURCE_NVD = "nvd_cve_api"

DEFAULT_OVERLAP = timedelta(minutes=10)
DEFAULT_LOOKBACK = timedelta(days=1)

WATERMARK_SCHEMA = StructType(
    [
        StructField("source", StringType(), nullable=False),
        StructField("watermark_ts", TimestampType(), nullable=False),
        StructField("batch_id", StringType(), nullable=False),
        StructField("load_timestamp", TimestampType(), nullable=False),
    ]
)


def incremental_window(
    watermark: datetime | None,
    now: datetime,
    *,
    seed_start: datetime | None = None,
    overlap: timedelta = DEFAULT_OVERLAP,
    default_lookback: timedelta = DEFAULT_LOOKBACK,
) -> tuple[datetime, datetime]:
    """Decide ``[start, end)`` for an INCREMENTAL run.

    * watermark known      -> start = watermark - overlap
    * first run, seed given -> start = seed_start
    * first run, no seed    -> start = now - default_lookback
    """
    if watermark is not None:
        start = watermark - overlap
    elif seed_start is not None:
        start = seed_start
    else:
        start = now - default_lookback
    if start >= now:
        raise ValueError(f"computed window is empty: start={start} now={now}")
    return start, now


def ensure_table(spark: SparkSession, table_fqn: str) -> None:
    columns = ", ".join(f"{f.name} {f.dataType.simpleString()}" for f in WATERMARK_SCHEMA.fields)
    spark.sql(
        f"CREATE TABLE IF NOT EXISTS {table_fqn} ({columns}) USING DELTA "
        "COMMENT 'Incremental high-water marks per source; current value is max(watermark_ts)'"
    )


def read_watermark(spark: SparkSession, table_fqn: str, source: str) -> datetime | None:
    row = (
        spark.table(table_fqn)
        .where(F.col("source") == source)
        .agg(F.max("watermark_ts").alias("wm"))
        .first()
    )
    value = row["wm"] if row else None
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def write_watermark(
    spark: SparkSession, table_fqn: str, source: str, watermark: datetime, batch_id: str
) -> None:
    now = datetime.now(timezone.utc).replace(tzinfo=None)
    wm = watermark.astimezone(timezone.utc).replace(tzinfo=None) if watermark.tzinfo else watermark
    df = spark.createDataFrame([(source, wm, batch_id, now)], schema=WATERMARK_SCHEMA)
    df.write.format("delta").mode("append").saveAsTable(table_fqn)
