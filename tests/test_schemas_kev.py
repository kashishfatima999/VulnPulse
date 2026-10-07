"""KEV catalog schema tests against the ten-record sample."""

import json

import pytest
from pyspark.sql import functions as F

from vulnpulse.schemas.kev import KEV_CATALOG_RAW_SCHEMA, KEV_KNOWN_KEYS, KEV_RECORD_SCHEMA

pytestmark = pytest.mark.spark

SAMPLE = "cisa_kev_sample.json"


def test_catalog_envelope_and_verbatim_entries(spark, data_dir):
    with open(data_dir / SAMPLE, encoding="utf-8") as fp:
        source = json.load(fp)

    catalog = (
        spark.read.schema(KEV_CATALOG_RAW_SCHEMA)
        .option("multiLine", True)
        .json(str(data_dir / SAMPLE))
    )
    row = catalog.first()
    assert row["catalogVersion"] == source["catalogVersion"]
    assert row["count"] == 10
    parsed = [json.loads(s) for s in row["vulnerabilities"]]
    assert parsed == source["vulnerabilities"]

    unknown = {k for rec in source["vulnerabilities"] for k in rec} - KEV_KNOWN_KEYS
    assert unknown == set(), f"unmodelled KEV keys: {unknown}"


def test_typed_record_schema(spark, data_dir):
    catalog = (
        spark.read.schema(KEV_CATALOG_RAW_SCHEMA)
        .option("multiLine", True)
        .json(str(data_dir / SAMPLE))
    )
    records = catalog.select(F.explode("vulnerabilities").alias("raw_json")).select(
        F.from_json("raw_json", KEV_RECORD_SCHEMA).alias("r")
    )
    rows = records.select("r.*").collect()
    assert len(rows) == 10
    assert all(r["cveID"].startswith("CVE-") for r in rows)
    assert all(r["dateAdded"] for r in rows)
