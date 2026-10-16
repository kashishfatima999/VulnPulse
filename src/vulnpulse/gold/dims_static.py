"""Static dimensions: dim_date and dim_severity.

Generated, not derived from Silver, so they are rebuilt and overwritten idempotently on every Gold
run (contract rule 23). Tiny tables; the overwrite costs nothing and guarantees completeness.
"""

from __future__ import annotations

from datetime import date, datetime, timezone

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F
from pyspark.sql.types import TimestampType

from vulnpulse.gold.ddl import DIM_DATE_SCHEMA, DIM_SEVERITY_SCHEMA
from vulnpulse.gold.keys import SEVERITY_ROWS

# Oldest CVE in NVD is from 1988; 2030 leaves headroom for KEV due dates.
DIM_DATE_START = date(1988, 1, 1)
DIM_DATE_END = date(2030, 12, 31)


def build_dim_date(
    spark: SparkSession,
    *,
    batch_id: str,
    load_timestamp: datetime,
    start: date = DIM_DATE_START,
    end: date = DIM_DATE_END,
) -> DataFrame:
    days = spark.sql(
        f"SELECT explode(sequence(to_date('{start.isoformat()}'), "
        f"to_date('{end.isoformat()}'), interval 1 day)) AS full_date"
    )
    d = F.col("full_date")
    return days.select(
        (F.year(d) * 10000 + F.month(d) * 100 + F.dayofmonth(d)).cast("int").alias("date_key"),
        d,
        F.year(d).cast("int").alias("year"),
        F.quarter(d).cast("int").alias("quarter"),
        F.month(d).cast("int").alias("month"),
        F.date_format(d, "MMMM").alias("month_name"),
        F.date_format(d, "yyyy-MM").alias("year_month"),
        F.dayofmonth(d).cast("int").alias("day"),
        # Spark dayofweek: 1 = Sunday .. 7 = Saturday. Convert to ISO: 1 = Monday .. 7 = Sunday.
        (((F.dayofweek(d) + 5) % 7) + 1).cast("int").alias("day_of_week"),
        F.date_format(d, "EEEE").alias("day_name"),
        F.weekofyear(d).cast("int").alias("week_of_year"),
        F.dayofweek(d).isin(1, 7).alias("is_weekend"),
        F.lit(batch_id).alias("batch_id"),
        F.lit(_naive_utc(load_timestamp)).cast(TimestampType()).alias("load_timestamp"),
    ).select(*[f.name for f in DIM_DATE_SCHEMA.fields])


def build_dim_severity(
    spark: SparkSession, *, batch_id: str, load_timestamp: datetime
) -> DataFrame:
    rows = [
        (key, label, lo, hi, order, desc, batch_id, _naive_utc(load_timestamp))
        for key, label, lo, hi, order, desc in SEVERITY_ROWS
    ]
    return spark.createDataFrame(rows, schema=DIM_SEVERITY_SCHEMA)


def overwrite(df: DataFrame, table_fqn: str) -> int:
    """Full overwrite for static dimensions; returns rows written."""
    df.write.format("delta").mode("overwrite").option("overwriteSchema", "true").saveAsTable(
        table_fqn
    )
    return df.count()


def _naive_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts
    return ts.astimezone(timezone.utc).replace(tzinfo=None)
