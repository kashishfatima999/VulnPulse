"""Bronze-to-Silver tests for CISA KEV and the Silver run parameters."""

from datetime import date, datetime, timezone

import pytest

from vulnpulse.bronze import kev as bronze_kev
from vulnpulse.silver import kev as kev_tf
from vulnpulse.silver import merge, quality
from vulnpulse.silver.ddl import SILVER_KEV_SCHEMA
from vulnpulse.silver.params import SilverRunParams, filter_bronze

SAMPLE = "cisa_kev_sample.json"
# Midday, so the calendar date is the same in any local time zone the test runner uses.
TS = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def bronze(spark, data_dir):
    entries = bronze_kev.explode_entries(bronze_kev.read_catalog(spark, str(data_dir / SAMPLE)))
    return bronze_kev.to_bronze(
        entries, source_uri="sample", load_type="FULL", batch_id="k1", load_timestamp=TS
    )


@pytest.mark.spark
def test_kev_columns_types_and_dates(bronze):
    out = kev_tf.transform_kev(bronze, load_timestamp=TS)
    silver = out.select(*kev_tf.SILVER_KEV_COLUMNS)
    assert silver.columns == [f.name for f in SILVER_KEV_SCHEMA.fields]
    types = dict(silver.dtypes)
    assert types["date_added"] == "date"
    assert types["due_date"] == "date"
    rows = out.collect()
    assert len(rows) == 10
    assert all(isinstance(r["date_added"], date) for r in rows)
    assert all(r["vendor_project"] for r in rows)


@pytest.mark.spark
def test_kev_quality_and_dedup(bronze):
    shaped = kev_tf.transform_kev(bronze.unionByName(bronze), load_timestamp=TS)
    valid, bad = quality.split_valid_invalid(shaped, quality.kev_rules(), source_table="t")
    assert bad.count() == 0
    assert merge.dedup_latest(valid, "cve_id", kev_tf.KEV_DEDUP_ORDER).count() == 10


def test_params_label_and_backfill():
    assert SilverRunParams().load_type == "FULL"
    assert SilverRunParams(batch_id="b").load_type == "BACKFILL"
    assert SilverRunParams(from_date="2026-10-01").load_type == "BACKFILL"
    assert SilverRunParams().run_id != SilverRunParams().run_id
    p = SilverRunParams(catalog="c")
    assert (p.bronze_schema, p.silver_schema, p.gold_schema) == (
        "c.vulnpulse_bronze",
        "c.vulnpulse_silver",
        "c.vulnpulse_gold",
    )


@pytest.mark.spark
def test_filter_bronze_by_batch_and_dates(bronze):
    assert filter_bronze(bronze, SilverRunParams()).count() == 10
    assert filter_bronze(bronze, SilverRunParams(batch_id="k1")).count() == 10
    assert filter_bronze(bronze, SilverRunParams(batch_id="other")).count() == 0
    assert filter_bronze(bronze, SilverRunParams(from_date="2026-10-09")).count() == 10
    assert filter_bronze(bronze, SilverRunParams(to_date="2026-10-08")).count() == 0
