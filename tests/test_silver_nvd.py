"""Bronze-to-Silver tests for NVD: casting, PII rule, schema drift, quality split, dedup.

``MERGE INTO`` itself needs Delta and runs in Databricks (evidence in docs/EVIDENCE.md); here we
test everything that decides what the MERGE receives.
"""

import json
from datetime import datetime, timezone

import pytest
from pyspark.sql import functions as F
from pyspark.sql.types import DoubleType, TimestampType

from vulnpulse.bronze import nvd as bronze_nvd
from vulnpulse.silver import merge, quality
from vulnpulse.silver import transform as tf
from vulnpulse.silver.ddl import SILVER_CVE_SCHEMA

pytestmark = pytest.mark.spark

SAMPLE = "nvd_full_load_sample.json"
TS = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)


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


def _bronze_row(spark, raw: dict, cve_id, batch_id="b1"):
    text = json.dumps(raw)
    df = spark.createDataFrame([(text,)], "raw_json string")
    df = bronze_nvd.to_bronze(
        df, source_uri="t", load_type="FULL", batch_id=batch_id, load_timestamp=TS
    )
    return df.withColumn("cve_id", F.lit(cve_id).cast("string"))


def test_columns_and_types_match_silver_table(bronze):
    out = tf.transform_nvd(bronze, load_timestamp=TS).select(*tf.SILVER_CVE_COLUMNS)
    assert out.columns == [f.name for f in SILVER_CVE_SCHEMA.fields]
    types = dict(out.dtypes)
    assert types["published_at"] == "timestamp"
    assert types["last_modified_at"] == "timestamp"
    assert types["cvss_v3_score"] == "double"
    assert types["has_source_identifier"] == "boolean"
    assert isinstance(out.schema["load_timestamp"].dataType, TimestampType)


def test_every_sample_record_parses(bronze, sample_cves):
    rows = tf.transform_nvd(bronze, load_timestamp=TS).collect()
    assert len(rows) == len(sample_cves) == 10
    for r in rows:
        src = sample_cves[r["cve_id"]]
        assert r["published_at"] is not None
        assert r["last_modified_at"] is not None
        assert r["vuln_status"] == src["vulnStatus"]
        english = [d["value"] for d in src["descriptions"] if d["lang"] == "en"]
        assert r["description_en"] == english[0]
        assert r["batch_id"] == "b1"
        assert r["unknown_keys"] == []


def test_timestamp_is_utc_wall_clock(bronze, sample_cves):
    """NVD's zone-less strings are UTC: rendered in the UTC session they must read back unchanged."""
    fmt = "yyyy-MM-dd'T'HH:mm:ss.SSS"
    rows = (
        tf.transform_nvd(bronze, load_timestamp=TS)
        .select("cve_id", F.date_format("last_modified_at", fmt).alias("s"))
        .collect()
    )
    for r in rows:
        assert r["s"] == sample_cves[r["cve_id"]]["lastModified"]


def test_pii_source_identifier_never_kept(bronze):
    out = tf.transform_nvd(bronze, load_timestamp=TS)
    assert "sourceIdentifier" not in out.columns
    assert "source_identifier" not in out.columns
    assert all(r["has_source_identifier"] for r in out.collect())


def test_cvss_v31_preferred_and_stringified_score_casts(spark, sample_cves):
    base = next(iter(sample_cves.values()))
    raw = dict(base)
    raw["metrics"] = {
        "cvssMetricV31": [
            {
                "source": "x",
                "type": "Secondary",
                "cvssData": {"baseScore": 5.0, "baseSeverity": "MEDIUM", "vectorString": "s"},
            },
            {
                "source": "nvd@nist.gov",
                "type": "Primary",
                "cvssData": {"baseScore": 9.8, "baseSeverity": "critical", "vectorString": "p"},
            },
        ],
        "cvssMetricV30": [{"type": "Primary", "cvssData": {"baseScore": 1.0}}],
    }
    row = tf.transform_nvd(_bronze_row(spark, raw, raw["id"]), load_timestamp=TS).first()
    assert row["cvss_v3_score"] == 9.8
    assert row["cvss_v3_severity"] == "CRITICAL"
    assert row["cvss_vector"] == "p"

    raw["metrics"] = {"cvssMetricV31": [{"type": "Primary", "cvssData": {"baseScore": "7.5"}}]}
    row = tf.transform_nvd(_bronze_row(spark, raw, raw["id"]), load_timestamp=TS).first()
    assert row["cvss_v3_score"] == 7.5
    assert isinstance(
        tf.transform_nvd(_bronze_row(spark, raw, raw["id"]), load_timestamp=TS)
        .schema["cvss_v3_score"]
        .dataType,
        DoubleType,
    )


def test_unknown_top_level_key_is_flagged_not_fatal(spark, sample_cves):
    raw = dict(next(iter(sample_cves.values())))
    raw["brandNewField"] = {"anything": 1}
    row = tf.transform_nvd(_bronze_row(spark, raw, raw["id"]), load_timestamp=TS).first()
    assert row["unknown_keys"] == ["brandNewField"]
    assert row["published_at"] is not None


def test_quality_split_routes_bad_rows_with_reason(spark, sample_cves):
    good = dict(next(iter(sample_cves.values())))
    bad_date = dict(good, published="not-a-date")
    bronze = (
        _bronze_row(spark, good, good["id"], "ok")
        .unionByName(_bronze_row(spark, good, None, "no-id"))
        .unionByName(_bronze_row(spark, good, "CVE-XYZ", "bad-id"))
        .unionByName(_bronze_row(spark, bad_date, "CVE-2099-0001", "bad-date"))
    )
    shaped = tf.transform_nvd(bronze, load_timestamp=TS)
    valid, bad = quality.split_valid_invalid(shaped, quality.nvd_rules(), source_table="t")

    assert [r["batch_id"] for r in valid.collect()] == ["ok"]
    reasons = {r["batch_id"]: r["reason"] for r in bad.collect()}
    assert reasons == {
        "no-id": quality.REASON_MISSING_ID,
        "bad-id": quality.REASON_BAD_ID,
        "bad-date": quality.REASON_BAD_PUBLISHED,
    }
    assert bad.columns == quality.QUARANTINE_COLUMNS


def test_dedup_keeps_latest_and_is_deterministic(spark, sample_cves):
    old = dict(next(iter(sample_cves.values())))
    new = dict(old, lastModified="2030-01-01T00:00:00.000")
    bronze = (
        _bronze_row(spark, old, old["id"], "b1")
        .unionByName(_bronze_row(spark, new, old["id"], "b2"))
        .unionByName(_bronze_row(spark, old, old["id"], "b3"))
    )
    shaped = tf.transform_nvd(bronze, load_timestamp=TS)
    order = ["last_modified_at", "batch_id", "payload_sha256"]
    rows = merge.dedup_latest(shaped, "cve_id", order).collect()
    assert len(rows) == 1
    assert rows[0]["batch_id"] == "b2"
    assert rows[0]["last_modified_at"].year == 2030


def test_same_bronze_twice_gives_identical_merge_source(bronze):
    """Idempotency at the DataFrame level: duplicated Bronze collapses to the same rows."""
    order = ["last_modified_at", "batch_id", "payload_sha256"]
    once = merge.dedup_latest(tf.transform_nvd(bronze, load_timestamp=TS), "cve_id", order)
    twice = merge.dedup_latest(
        tf.transform_nvd(bronze.unionByName(bronze), load_timestamp=TS), "cve_id", order
    )
    cols = tf.SILVER_CVE_COLUMNS
    assert sorted(once.select(*cols).collect()) == sorted(twice.select(*cols).collect())
    assert twice.count() == 10
