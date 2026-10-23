"""Bronze-to-Silver for ``silver_affected_product``: one row per CVE x CPE match criterion.

Source: ``configurations[].nodes[].cpeMatch[]`` in each NVD record. Each ``criteria`` is a CPE 2.3
formatted string with 13 colon-separated fields::

    cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:...
    cpe:2.3:a:neovim:neovim:*:*:*:*:*:*:*:*

A colon inside a field is escaped as ``\\:``, so the split is on *unescaped* colons only. Criteria
that do not parse into a concrete vendor and product are quarantined with a reason, never dropped.

Only the latest version of each CVE in Bronze is exploded (same dedup rule as ``silver_cve``), so a
CVE's products always come from one consistent record.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pyspark.sql import Column, DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import TimestampType

from vulnpulse.schemas.nvd import NVD_CVE_SCHEMA
from vulnpulse.silver import quality
from vulnpulse.silver.ddl import SILVER_AFFECTED_PRODUCT_SCHEMA
from vulnpulse.silver.merge import dedup_latest
from vulnpulse.silver.transform import parse_nvd_ts

SILVER_AFFECTED_PRODUCT_COLUMNS = [f.name for f in SILVER_AFFECTED_PRODUCT_SCHEMA.fields]
PRODUCT_KEY = ["cve_id", "criteria"]

# Split on ':' not preceded by a backslash (Java regex, used by Spark's split).
_UNESCAPED_COLON = r"(?<!\\):"


def latest_cve_versions(bronze: DataFrame) -> DataFrame:
    """One Bronze row per valid ``cve_id``: the latest ``lastModified`` (ties: batch, hash).

    Rows with a missing or malformed id are skipped here; the ``silver_cve`` run already
    quarantines them, so child tables do not quarantine the same record twice.
    """
    df = bronze.select(
        F.trim(F.col("cve_id")).alias("cve_id"),
        F.col("raw_json"),
        F.col("payload_sha256"),
        F.col("batch_id"),
        parse_nvd_ts(F.get_json_object(F.col("raw_json"), "$.lastModified")).alias(
            "last_modified_at"
        ),
    ).where(F.coalesce(F.col("cve_id").rlike(quality.CVE_ID_PATTERN), F.lit(False)))
    return dedup_latest(df, "cve_id", ["last_modified_at", "batch_id", "payload_sha256"])


def _field(parts: Column, n: int) -> Column:
    """n-th CPE field (1-based), unescaped; NULL when the criterion is too short."""
    return F.regexp_replace(F.try_element_at(parts, F.lit(n)), r"\\(.)", "$1")


def transform_products(bronze: DataFrame, *, load_timestamp: datetime) -> DataFrame:
    """Bronze NVD rows to Silver-shaped product rows.

    Output: ``SILVER_AFFECTED_PRODUCT_COLUMNS`` plus helpers for the quality step: ``raw_json``
    (the criterion itself, kept for quarantine) and ``_cpe_fields`` (number of CPE fields).
    """
    latest = latest_cve_versions(bronze)
    cve = F.from_json(F.col("raw_json"), NVD_CVE_SCHEMA)
    matches = (
        latest.select("*", F.explode(cve["configurations"]).alias("_conf"))
        .select("*", F.explode(F.col("_conf")["nodes"]).alias("_node"))
        .select("*", F.explode(F.col("_node")["cpeMatch"]).alias("m"))
    )
    parts = F.split(F.col("m")["criteria"], _UNESCAPED_COLON)
    ts = _naive_utc(load_timestamp)
    return matches.select(
        F.col("cve_id"),
        F.trim(F.col("m")["criteria"]).alias("criteria"),
        _field(parts, 3).alias("part"),
        _field(parts, 4).alias("vendor"),
        _field(parts, 5).alias("product"),
        _field(parts, 6).alias("version"),
        F.col("m")["vulnerable"].alias("vulnerable"),
        F.col("m")["versionStartIncluding"].alias("version_start_including"),
        F.col("m")["versionStartExcluding"].alias("version_start_excluding"),
        F.col("m")["versionEndIncluding"].alias("version_end_including"),
        F.col("m")["versionEndExcluding"].alias("version_end_excluding"),
        F.col("last_modified_at"),
        F.col("payload_sha256"),
        F.col("batch_id"),
        F.lit(ts).cast(TimestampType()).alias("load_timestamp"),
        F.col("m")["criteria"].alias("raw_json"),
        F.size(parts).alias("_cpe_fields"),
    )


def split_and_dedup(shaped: DataFrame, *, source_table: str) -> tuple[DataFrame, DataFrame]:
    """Quality split, then one row per (cve_id, criteria) for the MERGE.

    The same criterion can appear in two configuration nodes; the vulnerable entry wins. The
    quarantine hash is per criterion, so two bad criteria in one CVE are two quarantine rows.
    """
    valid, bad = quality.split_valid_invalid(
        shaped, quality.product_rules(), source_table=source_table
    )
    latest = dedup_latest(
        valid,
        PRODUCT_KEY,
        [
            "vulnerable",
            "version_end_excluding",
            "version_end_including",
            "version_start_including",
            "version_start_excluding",
        ],
    ).select(*SILVER_AFFECTED_PRODUCT_COLUMNS)
    bad = bad.withColumn(
        "payload_sha256",
        F.sha2(F.concat_ws("|", F.col("payload_sha256"), F.col("raw_json")), 256),
    )
    return latest, bad


def _naive_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts
    return ts.astimezone(timezone.utc).replace(tzinfo=None)
