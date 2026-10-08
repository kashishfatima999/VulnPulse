"""Raw-to-Bronze tests for the CISA KEV catalog against the ten-record sample."""

import json
from datetime import datetime, timezone

import pytest

from vulnpulse.bronze.kev import (
    BRONZE_KEV_SCHEMA,
    download_catalog,
    explode_entries,
    read_catalog,
    to_bronze,
)

pytestmark = pytest.mark.spark

SAMPLE = "cisa_kev_sample.json"


def test_explode_and_to_bronze(spark, data_dir):
    with open(data_dir / SAMPLE, encoding="utf-8") as fp:
        source = json.load(fp)

    entries = explode_entries(read_catalog(spark, str(data_dir / SAMPLE)))
    ts = datetime(2026, 10, 9, tzinfo=timezone.utc)
    df = to_bronze(entries, source_uri="s", load_type="FULL", batch_id="b", load_timestamp=ts)

    assert df.columns == [f.name for f in BRONZE_KEV_SCHEMA.fields]
    rows = df.orderBy("cve_id").collect()
    assert len(rows) == 10
    assert {r["cve_id"] for r in rows} == {v["cveID"] for v in source["vulnerabilities"]}
    assert all(r["catalog_version"] == source["catalogVersion"] for r in rows)
    assert all(len(r["payload_sha256"]) == 64 for r in rows)
    assert all(json.loads(r["raw_json"])["cveID"] == r["cve_id"] for r in rows)


def test_download_catalog_writes_file(tmp_path):
    fake = {"catalogVersion": "x", "vulnerabilities": [{"cveID": "CVE-2026-0001"}]}
    path = download_catalog(str(tmp_path / "a" / "kev.json"), fetch_json=lambda url, key: fake)
    assert json.loads(open(path, encoding="utf-8").read()) == fake
