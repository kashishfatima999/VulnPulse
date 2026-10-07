"""The ``pipeline_execution_logs`` table and helpers to write to it.

Every run of every layer writes exactly one row, success or failure. The row carries what the
rubric asks for: the layer, the parameter or file processed, start and end time, status, and
row counts. Both Bronze (Kashish) and Silver (Zahra) write here with the same schema.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql.types import LongType, StringType, StructField, StructType, TimestampType

EXECUTION_LOG_TABLE = "pipeline_execution_logs"

LAYER_RAW_TO_BRONZE = "Raw-to-Bronze"
LAYER_BRONZE_TO_SILVER = "Bronze-to-Silver"

STATUS_SUCCESS = "SUCCESS"
STATUS_FAILURE = "FAILURE"

EXECUTION_LOG_SCHEMA = StructType(
    [
        StructField("batch_id", StringType(), nullable=False),
        StructField("layer", StringType(), nullable=False),
        StructField("source", StringType(), nullable=False),
        StructField("load_type", StringType(), nullable=False),
        StructField("parameters", StringType()),
        StructField("started_at", TimestampType(), nullable=False),
        StructField("finished_at", TimestampType(), nullable=False),
        StructField("status", StringType(), nullable=False),
        StructField("rows_read", LongType()),
        StructField("rows_inserted", LongType()),
        StructField("rows_updated", LongType()),
        StructField("rows_quarantined", LongType()),
        StructField("error_message", StringType()),
        StructField("load_timestamp", TimestampType(), nullable=False),
    ]
)


def build_log_row(
    spark: SparkSession,
    *,
    batch_id: str,
    layer: str,
    source: str,
    load_type: str,
    parameters: dict | None,
    started_at: datetime,
    finished_at: datetime,
    status: str,
    rows_read: int | None = None,
    rows_inserted: int | None = None,
    rows_updated: int | None = None,
    rows_quarantined: int | None = None,
    error_message: str | None = None,
) -> DataFrame:
    """A one-row DataFrame in ``EXECUTION_LOG_SCHEMA``."""
    if status not in (STATUS_SUCCESS, STATUS_FAILURE):
        raise ValueError(f"status must be {STATUS_SUCCESS} or {STATUS_FAILURE}, got {status!r}")
    row = (
        batch_id,
        layer,
        source,
        load_type,
        json.dumps(parameters, sort_keys=True, default=str) if parameters is not None else None,
        _naive_utc(started_at),
        _naive_utc(finished_at),
        status,
        rows_read,
        rows_inserted,
        rows_updated,
        rows_quarantined,
        error_message,
        _naive_utc(finished_at),
    )
    return spark.createDataFrame([row], schema=EXECUTION_LOG_SCHEMA)


def ensure_table(spark: SparkSession, table_fqn: str) -> None:
    columns = ", ".join(
        f"{f.name} {f.dataType.simpleString()}" for f in EXECUTION_LOG_SCHEMA.fields
    )
    spark.sql(
        f"CREATE TABLE IF NOT EXISTS {table_fqn} ({columns}) USING DELTA "
        "COMMENT 'One row per pipeline run per layer: parameters, timing, status, row counts'"
    )


def append(df: DataFrame, table_fqn: str) -> None:
    df.write.format("delta").mode("append").saveAsTable(table_fqn)


def _naive_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts
    return ts.astimezone(timezone.utc).replace(tzinfo=None)
