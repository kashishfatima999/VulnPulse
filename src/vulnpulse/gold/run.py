"""Gold refresh scope: watermark on Silver ``load_timestamp`` and the changed-CVE set.

How incremental Gold works (contract rule 24):

    pipeline_watermarks (source = gold_from_silver) holds the max Silver load_timestamp already
    folded into Gold. A run collects every cve_id whose row in *any* Silver table was loaded after
    that instant (a KEV change or a new product row also changes the CVE's fact row), rebuilds those
    CVEs across dim_cve / fact_cve with MERGE, and advances the watermark to the max load_timestamp
    it saw, only after success. First run (no watermark) and ``mode=full`` process everything.

Pure helpers take DataFrames so they are unit-tested locally; the notebook supplies the tables.
"""

from __future__ import annotations

from datetime import datetime, timezone
from functools import reduce

from pyspark.sql import DataFrame, SparkSession
from pyspark.sql import functions as F

from vulnpulse.utils import watermark as wm

SOURCE_GOLD = "gold_from_silver"

# Silver tables that carry a cve_id and a load_timestamp. Optional ones may not exist yet.
SILVER_CVE_SOURCES = ("silver_cve", "silver_kev", "silver_affected_product", "silver_cwe")


def existing_silver_frames(spark: SparkSession, silver_schema: str) -> dict[str, DataFrame]:
    frames = {}
    for name in SILVER_CVE_SOURCES:
        fqn = f"{silver_schema}.{name}"
        if spark.catalog.tableExists(fqn):
            frames[name] = spark.table(fqn)
    return frames


def changed_cve_ids(frames: list[DataFrame], since: datetime | None) -> DataFrame:
    """Distinct ``cve_id`` loaded into any of ``frames`` after ``since`` (all ids when None)."""
    parts = []
    for df in frames:
        sel = df.select("cve_id", "load_timestamp")
        if since is not None:
            # A tz-aware literal is an exact instant; a naive one would be read in the local zone.
            sel = sel.where(F.col("load_timestamp") > F.lit(_aware_utc(since)))
        parts.append(sel.select("cve_id"))
    return reduce(DataFrame.unionByName, parts).where(F.col("cve_id").isNotNull()).distinct()


def scope_to(df: DataFrame, cve_ids: DataFrame | None) -> DataFrame:
    """Rows of ``df`` whose cve_id is in ``cve_ids``; unchanged when ``cve_ids`` is None (full)."""
    if cve_ids is None:
        return df
    return df.join(cve_ids, "cve_id", "left_semi")


def max_load_timestamp(frames: list[DataFrame]) -> datetime | None:
    """Largest Silver load_timestamp across ``frames``; the next Gold watermark."""
    maxes = [df.agg(F.max("load_timestamp").alias("m")).first()["m"] for df in frames]
    values = [_aware_utc(m) for m in maxes if m is not None]
    return max(values) if values else None


def read_gold_watermark(spark: SparkSession, watermark_table: str) -> datetime | None:
    return wm.read_watermark(spark, watermark_table, SOURCE_GOLD)


def write_gold_watermark(
    spark: SparkSession, watermark_table: str, value: datetime, run_id: str
) -> None:
    wm.write_watermark(spark, watermark_table, SOURCE_GOLD, value, run_id)


def _aware_utc(ts: datetime) -> datetime:
    """Spark returns naive datetimes in the machine's local zone; make them exact UTC instants."""
    return ts.astimezone(timezone.utc)
