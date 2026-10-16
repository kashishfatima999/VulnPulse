"""dim_cve / fact_cve builders and the Gold MERGE change predicate."""

from datetime import date, datetime, timezone

import pytest
from pyspark.sql import functions as F

from vulnpulse.gold.cve import FACT_CVE_COLUMNS, build_dim_cve, build_fact_cve, count_per_cve
from vulnpulse.gold.ddl import DIM_CVE_SCHEMA
from vulnpulse.gold.merge import changed_condition
from vulnpulse.silver.ddl import SILVER_CVE_SCHEMA, SILVER_KEV_SCHEMA

UTC = timezone.utc
TS = datetime(2026, 10, 17, 9, 0, tzinfo=UTC)
LOAD = datetime(2026, 10, 9, 16, 0, tzinfo=UTC)


def utc(*args):
    # Silver stores UTC instants; tz-aware fixtures keep the test independent of the laptop's zone.
    return datetime(*args, tzinfo=UTC)


@pytest.fixture(scope="module")
def silver_cve(spark):
    rows = [
        # cve_id, published, last_modified, status, desc, score, sev, vector, has_src, sha, batch, load_ts
        ("CVE-2024-0001", utc(2024, 1, 10, 12), utc(2026, 9, 1), "Analyzed", "a",
         9.8, "CRITICAL", "CVSS:3.1/AV:N", True, "h1", "b1", LOAD),
        ("CVE-2024-0002", utc(2024, 3, 5), utc(2026, 9, 2), "Modified", "b",
         5.3, "MEDIUM", "CVSS:3.1/AV:L", False, "h2", "b1", LOAD),
        ("CVE-2020-0003", utc(2020, 6, 1), utc(2020, 7, 1), "Analyzed", "c",
         None, None, None, True, "h3", "b1", LOAD),
    ]  # fmt: skip
    return spark.createDataFrame(rows, schema=SILVER_CVE_SCHEMA)


@pytest.fixture(scope="module")
def silver_kev(spark):
    rows = [
        ("CVE-2024-0001", "Acme", "Widget", "Acme Widget RCE", date(2024, 1, 25), date(2024, 2, 15),
         "Known", "Apply updates", "2026.10.04", "k1", "kb", LOAD),
    ]  # fmt: skip
    return spark.createDataFrame(rows, schema=SILVER_KEV_SCHEMA)


@pytest.mark.spark
def test_dim_cve_attributes_and_kev_flag(silver_cve, silver_kev):
    dim = build_dim_cve(silver_cve, silver_kev, batch_id="g", load_timestamp=TS)
    assert dim.columns == [f.name for f in DIM_CVE_SCHEMA.fields]
    rows = {r["cve_id"]: r for r in dim.collect()}
    assert len(rows) == 3
    a, b = rows["CVE-2024-0001"], rows["CVE-2024-0002"]
    assert a["is_in_kev"] is True and a["kev_vendor_project"] == "Acme"
    assert a["kev_due_date"] == date(2024, 2, 15)
    assert b["is_in_kev"] is False and b["kev_vendor_project"] is None
    assert all(r["batch_id"] == "g" for r in rows.values())
    # PII rule: the only source-identifier column in Gold is the boolean lineage flag
    assert [c for c in dim.columns if "source" in c.lower()] == ["has_source_identifier"]


@pytest.mark.spark
def test_fact_cve_keys_flags_and_days_to_kev(silver_cve, silver_kev):
    fact = build_fact_cve(silver_cve, silver_kev, batch_id="g", load_timestamp=TS)
    assert fact.columns == FACT_CVE_COLUMNS
    rows = {r["cve_id"]: r for r in fact.collect()}

    a = rows["CVE-2024-0001"]
    assert a["published_date_key"] == 20240110
    assert a["last_modified_date_key"] == 20260901
    assert a["kev_added_date_key"] == 20240125 and a["kev_due_date_key"] == 20240215
    assert a["severity_key"] == 1  # CRITICAL
    assert a["is_exploited"] == 1 and a["is_ransomware"] == 1
    assert a["days_to_kev"] == 15  # 10 Jan -> 25 Jan
    assert a["cve_count"] == 1

    b = rows["CVE-2024-0002"]
    assert b["severity_key"] == 3  # MEDIUM
    assert b["is_exploited"] == 0 and b["is_ransomware"] == 0
    assert b["days_to_kev"] is None and b["kev_added_date_key"] is None

    c = rows["CVE-2020-0003"]
    assert c["severity_key"] == 6  # UNKNOWN: no v3 metric
    assert c["product_count"] is None and c["cwe_count"] is None  # counts not supplied


@pytest.mark.spark
def test_fact_cve_attaches_child_counts(spark, silver_cve, silver_kev):
    products = spark.createDataFrame(
        [("CVE-2024-0001", "acme", "widget"), ("CVE-2024-0001", "acme", "gadget")],
        ["cve_id", "vendor", "product"],
    )
    fact = build_fact_cve(
        silver_cve,
        silver_kev,
        batch_id="g",
        load_timestamp=TS,
        product_counts=count_per_cve(products),
    )
    rows = {r["cve_id"]: r for r in fact.collect()}
    assert rows["CVE-2024-0001"]["product_count"] == 2
    assert rows["CVE-2024-0002"]["product_count"] is None  # no products known for it
    assert fact.where(F.col("cve_id").isNull()).count() == 0


def test_changed_condition_excludes_audit_columns():
    cond = changed_condition(["is_in_kev", "kev_product", "batch_id", "load_timestamp"])
    assert cond == "NOT (s.is_in_kev <=> t.is_in_kev AND s.kev_product <=> t.kev_product)"
    assert changed_condition(["batch_id", "load_timestamp"]) == "false"
