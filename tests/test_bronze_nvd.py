"""Raw-to-Bronze tests for NVD, run against the ten-record samples with a local SparkSession."""

import json
import re
from datetime import datetime, timezone

import pytest
from pyspark.sql import functions as F

from vulnpulse.bronze.nvd import BRONZE_NVD_SCHEMA, explode_cves, read_nvd_pages, to_bronze
from vulnpulse.schemas.nvd import NVD_CVE_KNOWN_KEYS, NVD_CVE_SCHEMA

pytestmark = pytest.mark.spark

SAMPLE = "nvd_incremental_load_sample.json"
CVE_ID = re.compile(r"^CVE-\d{4}-\d{4,}$")


@pytest.fixture(scope="module")
def sample_records(data_dir):
    with open(data_dir / SAMPLE, encoding="utf-8") as fp:
        return {v["cve"]["id"]: v["cve"] for v in json.load(fp)["vulnerabilities"]}


@pytest.fixture(scope="module")
def raw(spark, data_dir):
    return explode_cves(read_nvd_pages(spark, str(data_dir / SAMPLE))).cache()


def test_page_envelope_is_typed(spark, data_dir):
    pages = read_nvd_pages(spark, str(data_dir / SAMPLE))
    row = pages.first()
    assert pages.count() == 1
    assert isinstance(row["totalResults"], int)
    assert row["format"] == "NVD_CVE"
    assert len(row["vulnerabilities"]) == 10


def test_raw_json_is_verbatim_source_record(raw, sample_records):
    """Every key and value of the source record survives, including ones our typed schema ignores."""
    rows = raw.collect()
    assert len(rows) == 10
    for row in rows:
        parsed = json.loads(row["raw_json"])
        assert parsed == sample_records[parsed["id"]]


def test_sample_contains_fields_outside_typed_schema(sample_records):
    """Documents real schema drift: NVD ships keys the proposal never modelled."""
    all_keys = {k for rec in sample_records.values() for k in rec}
    unknown = all_keys - NVD_CVE_KNOWN_KEYS
    assert "affected" in all_keys  # newer NVD addition, kept raw, not modelled
    assert unknown == set(), f"unmodelled keys appeared: {unknown}"


def test_to_bronze_matches_declared_schema(raw):
    ts = datetime(2026, 10, 8, 12, 0, tzinfo=timezone.utc)
    df = to_bronze(raw, source_uri="s", load_type="FULL", batch_id="b1", load_timestamp=ts)

    assert df.columns == [f.name for f in BRONZE_NVD_SCHEMA.fields]
    assert dict(df.dtypes)["load_timestamp"] == "timestamp"

    rows = df.collect()
    assert len(rows) == 10
    for r in rows:
        assert CVE_ID.match(r["cve_id"])
        assert r["source_last_modified"]
        assert len(r["payload_sha256"]) == 64
        assert (r["source_uri"], r["load_type"], r["batch_id"]) == ("s", "FULL", "b1")
        assert r["load_timestamp"] == ts.replace(tzinfo=None)


def test_same_payload_hashes_identically(raw):
    """Re-ingesting the same record yields the same payload_sha256; Silver relies on this."""
    a = to_bronze(raw, source_uri="s", load_type="FULL", batch_id="b1", load_timestamp=_now())
    b = to_bronze(raw, source_uri="s", load_type="FULL", batch_id="b2", load_timestamp=_now())
    joined = a.alias("a").join(b.alias("b"), "cve_id").where("a.payload_sha256 <> b.payload_sha256")
    assert joined.count() == 0


def test_typed_cve_schema_parses_raw_json(raw):
    typed = raw.select(F.from_json("raw_json", NVD_CVE_SCHEMA).alias("cve")).select("cve.*")
    vim = typed.where("id = 'CVE-2022-3324'").first()
    assert vim is not None
    assert vim["metrics"]["cvssMetricV31"][0]["cvssData"]["baseScore"] == 7.8
    assert vim["metrics"]["cvssMetricV31"][0]["cvssData"]["baseSeverity"] == "HIGH"
    assert vim["weaknesses"][0]["description"][0]["value"].startswith("CWE-")
    assert vim["configurations"][0]["nodes"][0]["cpeMatch"][0]["criteria"].startswith("cpe:2.3:")
    # No record should fail to parse: from_json yields null id only on corrupt input.
    assert typed.where("id IS NULL").count() == 0


def _now():
    return datetime.now(timezone.utc)
