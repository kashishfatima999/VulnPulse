"""Bronze-to-Silver for ``silver_cwe``: one row per CVE x weakness id.

Source: ``weaknesses[].description[].value`` where ``lang = 'en'``. NVD lists the same CWE once per
scoring source (Primary NVD, Secondary CNA), so values are de-duplicated per CVE. The weakness
``source`` is not kept: it can be a CNA e-mail address (same PII rule as ``sourceIdentifier``).

Accepted ids: ``CWE-<n>``, ``NVD-CWE-noinfo``, ``NVD-CWE-Other``. Anything else is quarantined.
"""

from __future__ import annotations

from datetime import datetime, timezone

from pyspark.sql import DataFrame
from pyspark.sql import functions as F
from pyspark.sql.types import TimestampType

from vulnpulse.schemas.nvd import NVD_CVE_SCHEMA
from vulnpulse.silver import quality
from vulnpulse.silver.ddl import SILVER_CWE_SCHEMA
from vulnpulse.silver.products import latest_cve_versions

SILVER_CWE_COLUMNS = [f.name for f in SILVER_CWE_SCHEMA.fields]
CWE_KEY = ["cve_id", "cwe_id"]


def transform_cwe(bronze: DataFrame, *, load_timestamp: datetime) -> DataFrame:
    """Bronze NVD rows to Silver-shaped CWE rows, plus ``raw_json`` (the raw value) for quarantine."""
    latest = latest_cve_versions(bronze)
    cve = F.from_json(F.col("raw_json"), NVD_CVE_SCHEMA)
    descriptions = (
        latest.select("*", F.explode(cve["weaknesses"]).alias("_w"))
        .select("*", F.explode(F.col("_w")["description"]).alias("d"))
        .where(F.col("d")["lang"] == "en")
    )
    ts = _naive_utc(load_timestamp)
    return descriptions.select(
        F.col("cve_id"),
        F.trim(F.col("d")["value"]).alias("cwe_id"),
        F.col("last_modified_at"),
        F.col("payload_sha256"),
        F.col("batch_id"),
        F.lit(ts).cast(TimestampType()).alias("load_timestamp"),
        F.col("d")["value"].alias("raw_json"),
    )


def split_and_dedup(shaped: DataFrame, *, source_table: str) -> tuple[DataFrame, DataFrame]:
    """Quality split, then one row per (cve_id, cwe_id). Quarantine hash is per raw value."""
    valid, bad = quality.split_valid_invalid(shaped, quality.cwe_rules(), source_table=source_table)
    latest = valid.dropDuplicates(CWE_KEY).select(*SILVER_CWE_COLUMNS)
    bad = bad.withColumn(
        "payload_sha256",
        F.sha2(F.concat_ws("|", F.col("payload_sha256"), F.col("raw_json")), 256),
    )
    return latest, bad


def _naive_utc(ts: datetime) -> datetime:
    if ts.tzinfo is None:
        return ts
    return ts.astimezone(timezone.utc).replace(tzinfo=None)
