"""Product and CWE arms of the Gold star: dim_vendor_product, fact_cve_product, dim_cwe, fact_cve_cwe."""

from datetime import date, datetime, timezone

import pytest

from vulnpulse.gold import cve as gold_cve
from vulnpulse.gold import cwe as gold_cwe
from vulnpulse.gold import products as gold_products
from vulnpulse.gold.ddl import (
    DIM_CWE_SCHEMA,
    DIM_VENDOR_PRODUCT_SCHEMA,
    FACT_CVE_CWE_SCHEMA,
    FACT_CVE_PRODUCT_SCHEMA,
)
from vulnpulse.gold.keys import CWE_KEY_NOINFO, CWE_KEY_OTHER
from vulnpulse.silver.ddl import (
    SILVER_AFFECTED_PRODUCT_SCHEMA,
    SILVER_CVE_SCHEMA,
    SILVER_CWE_SCHEMA,
    SILVER_KEV_SCHEMA,
)

pytestmark = pytest.mark.spark

UTC = timezone.utc
TS = datetime(2026, 10, 23, 9, 0, tzinfo=UTC)
LOAD = datetime(2026, 10, 22, 16, 0, tzinfo=UTC)


def utc(*args):
    return datetime(*args, tzinfo=UTC)


@pytest.fixture(scope="module")
def silver_cve(spark):
    rows = [
        ("CVE-2024-0001", utc(2024, 1, 10, 12), utc(2026, 9, 1), "Analyzed", "a",
         9.8, "CRITICAL", "v", True, "h1", "b1", LOAD),
        ("CVE-2024-0002", utc(2024, 3, 5), utc(2026, 9, 2), "Modified", "b",
         5.3, "MEDIUM", "v", False, "h2", "b1", LOAD),
    ]  # fmt: skip
    return spark.createDataFrame(rows, schema=SILVER_CVE_SCHEMA)


@pytest.fixture(scope="module")
def silver_kev(spark):
    rows = [
        ("CVE-2024-0001", "Acme", "Widget", "RCE", date(2024, 1, 25), date(2024, 2, 15),
         "Known", "Patch", "2026.10.04", "k1", "kb", LOAD),
    ]  # fmt: skip
    return spark.createDataFrame(rows, schema=SILVER_KEV_SCHEMA)


@pytest.fixture(scope="module")
def silver_products(spark):
    def row(cve, crit, part, vendor, product, vulnerable):
        return (cve, crit, part, vendor, product, "*", vulnerable,
                None, None, None, None, utc(2026, 9, 1), "h", "b1", LOAD)  # fmt: skip

    rows = [
        row("CVE-2024-0001", "c1", "a", "acme", "widget", True),
        row("CVE-2024-0001", "c2", "a", "acme", "widget", True),  # same product, other version
        row("CVE-2024-0001", "c3", "o", "microsoft", "windows", False),  # platform, not affected
        row("CVE-2024-0002", "c4", "a", "ACME ", "Widget", True),  # same pair, other casing
        row("CVE-2024-0002", "c5", "a", "globex", "portal", True),
        row("CVE-2099-0009", "c6", "a", "orphan", "thing", True),  # no silver_cve row
    ]
    return spark.createDataFrame(rows, schema=SILVER_AFFECTED_PRODUCT_SCHEMA)


@pytest.fixture(scope="module")
def silver_cwes(spark):
    rows = [
        ("CVE-2024-0001", "CWE-79", utc(2026, 9, 1), "h", "b1", LOAD),
        ("CVE-2024-0001", "NVD-CWE-noinfo", utc(2026, 9, 1), "h", "b1", LOAD),
        ("CVE-2024-0002", "CWE-79", utc(2026, 9, 2), "h", "b1", LOAD),
        ("CVE-2024-0002", "NVD-CWE-Other", utc(2026, 9, 2), "h", "b1", LOAD),
        ("CVE-2099-0009", "CWE-89", utc(2026, 9, 2), "h", "b1", LOAD),  # no silver_cve row
    ]
    return spark.createDataFrame(rows, schema=SILVER_CWE_SCHEMA)


def test_dim_vendor_product(silver_products):
    dim = gold_products.build_dim_vendor_product(silver_products, batch_id="g", load_timestamp=TS)
    assert dim.columns == [f.name for f in DIM_VENDOR_PRODUCT_SCHEMA.fields]
    rows = {(r["vendor"], r["product"]): r for r in dim.collect()}
    # 'ACME '/'Widget' folds into acme/widget; the non-vulnerable platform row is not a product
    assert set(rows) == {("acme", "widget"), ("globex", "portal"), ("orphan", "thing")}
    assert dim.count() == dim.select("vendor_product_key").distinct().count()
    assert rows[("acme", "widget")]["part"] == "a"
    assert all(r["batch_id"] == "g" for r in rows.values())


def test_fact_cve_product_grain_keys_and_flags(silver_products, silver_cve, silver_kev):
    fact = gold_products.build_fact_cve_product(
        silver_products, silver_cve, silver_kev, batch_id="g", load_timestamp=TS
    )
    dim = gold_products.build_dim_vendor_product(silver_products, batch_id="g", load_timestamp=TS)
    assert fact.columns == [f.name for f in FACT_CVE_PRODUCT_SCHEMA.fields]
    names = {r["vendor_product_key"]: (r["vendor"], r["product"]) for r in dim.collect()}
    rows = {(r["cve_id"], names[r["vendor_product_key"]]): r for r in fact.collect()}
    assert set(rows) == {
        ("CVE-2024-0001", ("acme", "widget")),  # two criteria, one fact row
        ("CVE-2024-0002", ("acme", "widget")),
        ("CVE-2024-0002", ("globex", "portal")),
    }  # orphan CVE without a silver_cve row is left out
    a = rows[("CVE-2024-0001", ("acme", "widget"))]
    assert (a["is_exploited"], a["published_date_key"], a["cvss_v3_score"]) == (1, 20240110, 9.8)
    assert rows[("CVE-2024-0002", ("globex", "portal"))]["is_exploited"] == 0


def test_bridge_facts_agree_with_fact_cve(silver_products, silver_cwes, silver_cve, silver_kev):
    core = {
        r["cve_id"]: r
        for r in gold_cve.build_fact_cve(
            silver_cve, silver_kev, batch_id="g", load_timestamp=TS
        ).collect()
    }
    bridges = (
        gold_products.build_fact_cve_product(
            silver_products, silver_cve, silver_kev, batch_id="g", load_timestamp=TS
        ).collect()
        + gold_cwe.build_fact_cve_cwe(
            silver_cwes, silver_cve, silver_kev, batch_id="g", load_timestamp=TS
        ).collect()
    )
    for r in bridges:
        c = core[r["cve_id"]]
        for col in ("published_date_key", "severity_key", "is_exploited", "cvss_v3_score"):
            assert r[col] == c[col], (r["cve_id"], col)


def test_dim_cwe_keys_and_categories(silver_cwes):
    dim = gold_cwe.build_dim_cwe(silver_cwes, batch_id="g", load_timestamp=TS)
    assert dim.columns == [f.name for f in DIM_CWE_SCHEMA.fields]
    rows = {r["cwe_key"]: (r["cwe_id"], r["cwe_category"]) for r in dim.collect()}
    assert rows == {
        79: ("CWE-79", "CWE"),
        89: ("CWE-89", "CWE"),
        CWE_KEY_NOINFO: ("NVD-CWE-noinfo", "NVD-CWE-noinfo"),
        CWE_KEY_OTHER: ("NVD-CWE-Other", "NVD-CWE-Other"),
    }


def test_fact_cve_cwe(silver_cwes, silver_cve, silver_kev):
    fact = gold_cwe.build_fact_cve_cwe(
        silver_cwes, silver_cve, silver_kev, batch_id="g", load_timestamp=TS
    )
    assert fact.columns == [f.name for f in FACT_CVE_CWE_SCHEMA.fields]
    pairs = {(r["cve_id"], r["cwe_key"]) for r in fact.collect()}
    assert pairs == {
        ("CVE-2024-0001", 79),
        ("CVE-2024-0001", CWE_KEY_NOINFO),
        ("CVE-2024-0002", 79),
        ("CVE-2024-0002", CWE_KEY_OTHER),
    }
    assert fact.count() == len(pairs)


def test_builders_are_deterministic(silver_products, silver_cwes, silver_cve, silver_kev):
    """Same Silver in, same rows out: what makes the Gold MERGE re-run a no-op."""
    for build in (
        lambda: gold_products.build_dim_vendor_product(
            silver_products, batch_id="g", load_timestamp=TS
        ),
        lambda: gold_products.build_fact_cve_product(
            silver_products, silver_cve, silver_kev, batch_id="g", load_timestamp=TS
        ),
        lambda: gold_cwe.build_dim_cwe(silver_cwes, batch_id="g", load_timestamp=TS),
        lambda: gold_cwe.build_fact_cve_cwe(
            silver_cwes, silver_cve, silver_kev, batch_id="g", load_timestamp=TS
        ),
    ):
        assert sorted(build().collect()) == sorted(build().collect())
