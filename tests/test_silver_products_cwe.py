"""Bronze-to-Silver tests for the Phase 3 child tables: silver_affected_product and silver_cwe."""

import json
from datetime import datetime, timezone

import pytest
from pyspark.sql import functions as F

from vulnpulse.bronze import nvd as bronze_nvd
from vulnpulse.silver import cwe, products, quality
from vulnpulse.silver.ddl import SILVER_AFFECTED_PRODUCT_SCHEMA, SILVER_CWE_SCHEMA

pytestmark = pytest.mark.spark

SAMPLE = "nvd_full_load_sample.json"
TS = datetime(2026, 10, 23, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def bronze(spark, data_dir):
    raw = bronze_nvd.explode_cves(bronze_nvd.read_nvd_pages(spark, str(data_dir / SAMPLE)))
    return bronze_nvd.to_bronze(
        raw, source_uri="sample", load_type="FULL", batch_id="b1", load_timestamp=TS
    )


@pytest.fixture(scope="module")
def sample_cves(data_dir):
    with open(data_dir / SAMPLE, encoding="utf-8") as fp:
        return {v["cve"]["id"]: v["cve"] for v in json.load(fp)["vulnerabilities"]}


def _bronze(spark, records: list[tuple[dict, str]]):
    """Bronze rows from (record, batch_id) pairs."""
    df = None
    for raw, batch in records:
        one = bronze_nvd.to_bronze(
            spark.createDataFrame([(json.dumps(raw),)], "raw_json string"),
            source_uri="t",
            load_type="FULL",
            batch_id=batch,
            load_timestamp=TS,
        )
        df = one if df is None else df.unionByName(one)
    return df


def _record(cve_id, criteria=(), cwes=(), last_modified="2026-09-01T00:00:00.000"):
    matches = [
        {"vulnerable": vulnerable, "criteria": c, "matchCriteriaId": "x"}
        for c, vulnerable in criteria
    ]
    return {
        "id": cve_id,
        "published": "2026-08-01T00:00:00.000",
        "lastModified": last_modified,
        "configurations": [{"nodes": [{"operator": "OR", "negate": False, "cpeMatch": matches}]}],
        "weaknesses": [
            {"source": "cna@example.org", "type": "Secondary", "description": [d]} for d in cwes
        ],
    }


# ------------------------------------------------------------------------- silver_affected_product


def test_products_columns_match_table_and_sample_parses(bronze, sample_cves):
    shaped = products.transform_products(bronze, load_timestamp=TS)
    valid, bad = products.split_and_dedup(shaped, source_table="t")
    assert valid.columns == [f.name for f in SILVER_AFFECTED_PRODUCT_SCHEMA.fields]
    assert bad.count() == 0

    expected = {
        (cid, m["criteria"])
        for cid, c in sample_cves.items()
        for conf in c.get("configurations", [])
        for node in conf["nodes"]
        for m in node["cpeMatch"]
    }
    rows = valid.collect()
    assert {(r["cve_id"], r["criteria"]) for r in rows} == expected

    sendmail = next(r for r in rows if r["cve_id"] == "CVE-1999-0095")
    assert (sendmail["part"], sendmail["vendor"], sendmail["product"], sendmail["version"]) == (
        "a",
        "eric_allman",
        "sendmail",
        "5.58",
    )
    assert sendmail["vulnerable"] is True
    assert all(r["batch_id"] == "b1" and r["last_modified_at"] is not None for r in rows)


def test_escaped_colon_and_version_bounds(spark):
    raw = _record("CVE-2026-0001", [(r"cpe:2.3:a:foo\:bar:baz:*:*:*:*:*:*:*:*", True)])
    raw["configurations"][0]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"] = "2.0"
    shaped = products.transform_products(_bronze(spark, [(raw, "b")]), load_timestamp=TS)
    valid, bad = products.split_and_dedup(shaped, source_table="t")
    row = valid.first()
    assert bad.count() == 0
    assert (row["vendor"], row["product"], row["version_end_excluding"]) == (
        "foo:bar",
        "baz",
        "2.0",
    )


def test_bad_criteria_are_quarantined_one_row_each(spark):
    raw = _record(
        "CVE-2026-0002",
        [
            ("cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*", True),
            ("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*", True),  # no concrete vendor/product
            ("not-a-cpe", True),
            ("cpe:2.3:x:acme:widget:1.0:*:*:*:*:*:*:*", True),  # unknown part
        ],
    )
    shaped = products.transform_products(_bronze(spark, [(raw, "b")]), load_timestamp=TS)
    valid, bad = products.split_and_dedup(shaped, source_table="t")
    assert [r["product"] for r in valid.collect()] == ["widget"]
    rows = bad.collect()
    assert len(rows) == 3
    assert {r["reason"] for r in rows} == {quality.REASON_BAD_CPE}
    assert len({r["payload_sha256"] for r in rows}) == 3  # distinct, so the MERGE keeps all three


def test_duplicate_criterion_keeps_vulnerable_entry(spark):
    c = "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*"
    raw = _record("CVE-2026-0003", [(c, False), (c, True)])
    shaped = products.transform_products(_bronze(spark, [(raw, "b")]), load_timestamp=TS)
    valid, _ = products.split_and_dedup(shaped, source_table="t")
    rows = valid.collect()
    assert len(rows) == 1 and rows[0]["vulnerable"] is True


def test_only_latest_bronze_version_is_exploded(spark):
    old = _record("CVE-2026-0004", [("cpe:2.3:a:old:thing:1:*:*:*:*:*:*:*", True)])
    new = _record(
        "CVE-2026-0004",
        [("cpe:2.3:a:new:thing:2:*:*:*:*:*:*:*", True)],
        last_modified="2026-10-01T00:00:00.000",
    )
    bronze = _bronze(spark, [(old, "b1"), (new, "b2"), (old, "b3")])
    valid, _ = products.split_and_dedup(
        products.transform_products(bronze, load_timestamp=TS), source_table="t"
    )
    rows = valid.collect()
    assert [(r["vendor"], r["batch_id"]) for r in rows] == [("new", "b2")]


def test_products_rerun_on_duplicated_bronze_is_identical(bronze):
    once, _ = products.split_and_dedup(
        products.transform_products(bronze, load_timestamp=TS), source_table="t"
    )
    twice, _ = products.split_and_dedup(
        products.transform_products(bronze.unionByName(bronze), load_timestamp=TS),
        source_table="t",
    )
    assert sorted(once.collect()) == sorted(twice.collect())


# ----------------------------------------------------------------------------------- silver_cwe


def test_cwe_sample(bronze):
    valid, bad = cwe.split_and_dedup(cwe.transform_cwe(bronze, load_timestamp=TS), source_table="t")
    assert valid.columns == [f.name for f in SILVER_CWE_SCHEMA.fields]
    assert bad.count() == 0
    pairs = {(r["cve_id"], r["cwe_id"]) for r in valid.collect()}
    assert ("CVE-1999-0084", "CWE-269") in pairs
    assert ("CVE-1999-0084", "NVD-CWE-Other") in pairs
    assert valid.count() == len(pairs)  # one row per key


def test_cwe_dedup_language_filter_quarantine_and_no_pii(spark):
    raw = _record(
        "CVE-2026-0005",
        cwes=[
            {"lang": "en", "value": "CWE-416"},
            {"lang": "en", "value": "CWE-416"},  # same CWE from a second source
            {"lang": "es", "value": "CWE-999"},  # not English: ignored
            {"lang": "en", "value": "Use after free"},  # not an id: quarantined
            {"lang": "en", "value": "NVD-CWE-noinfo"},
        ],
    )
    valid, bad = cwe.split_and_dedup(
        cwe.transform_cwe(_bronze(spark, [(raw, "b")]), load_timestamp=TS), source_table="t"
    )
    assert sorted(r["cwe_id"] for r in valid.collect()) == ["CWE-416", "NVD-CWE-noinfo"]
    assert [(r["reason"], r["raw_json"]) for r in bad.collect()] == [
        (quality.REASON_BAD_CWE, "Use after free")
    ]
    # The weakness source can be a CNA e-mail address; it never reaches Silver.
    assert not [c for c in valid.columns if "source" in c.lower()]


def test_cve_without_weaknesses_or_configurations_yields_no_rows(spark):
    raw = {
        "id": "CVE-2026-0006",
        "published": "2026-08-01T00:00:00.000",
        "lastModified": "2026-09-01T00:00:00.000",
    }
    b = _bronze(spark, [(raw, "b")])
    assert products.transform_products(b, load_timestamp=TS).count() == 0
    assert cwe.transform_cwe(b, load_timestamp=TS).count() == 0


def test_child_tables_skip_rows_without_valid_id(spark):
    raw = _record(None, [("cpe:2.3:a:a:b:1:*:*:*:*:*:*:*", True)])
    b = _bronze(spark, [(raw, "b")]).withColumn("cve_id", F.lit(None).cast("string"))
    assert products.transform_products(b, load_timestamp=TS).count() == 0
