"""Key expressions and the generated static dimensions."""

from datetime import date, datetime, timezone

import pytest
from pyspark.sql import functions as F

from vulnpulse.gold import keys
from vulnpulse.gold.ddl import DIM_DATE_SCHEMA, DIM_SEVERITY_SCHEMA
from vulnpulse.gold.dims_static import build_dim_date, build_dim_severity

pytestmark = pytest.mark.spark

TS = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)


def test_date_key_from_timestamp_and_null(spark):
    df = spark.createDataFrame([("2026-09-24T15:38:04.713",), (None,)], ["ts"]).select(
        keys.date_key_expr(F.to_timestamp("ts")).alias("k")
    )
    assert [r["k"] for r in df.collect()] == [20260924, None]


def test_severity_key_prefers_label_then_score_then_unknown(spark):
    rows = [
        ("CRITICAL", 9.8),  # label
        (None, 7.5),  # score band -> HIGH
        ("high", 2.0),  # label wins even if score disagrees (NVD's label is authoritative)
        (None, 0.0),  # NONE
        (None, None),  # UNKNOWN
    ]
    df = spark.createDataFrame(rows, ["sev", "score"]).select(
        keys.severity_key_expr(F.col("sev"), F.col("score")).alias("k")
    )
    assert [r["k"] for r in df.collect()] == [1, 2, 2, 5, 6]


def test_vendor_product_key_is_case_and_space_insensitive(spark):
    df = spark.createDataFrame(
        [("Microsoft", "Windows"), (" microsoft ", "windows"), ("microsoft", "office")],
        ["v", "p"],
    ).select(keys.vendor_product_key_expr(F.col("v"), F.col("p")).alias("k"))
    a, b, c = [r["k"] for r in df.collect()]
    assert a == b and a != c


def test_cwe_key_and_category(spark):
    df = spark.createDataFrame(
        [("CWE-79",), ("NVD-CWE-noinfo",), ("NVD-CWE-Other",), ("garbage",)], ["id"]
    ).select(
        keys.cwe_key_expr(F.col("id")).alias("k"), keys.cwe_category_expr(F.col("id")).alias("c")
    )
    assert [(r["k"], r["c"]) for r in df.collect()] == [
        (79, "CWE"),
        (-1, "NVD-CWE-noinfo"),
        (-2, "NVD-CWE-Other"),
        (None, "CWE"),
    ]


def test_dim_date_shape_and_calendar_logic(spark):
    df = build_dim_date(
        spark, batch_id="b", load_timestamp=TS, start=date(2026, 1, 1), end=date(2026, 12, 31)
    )
    assert df.columns == [f.name for f in DIM_DATE_SCHEMA.fields]
    assert df.count() == 365
    row = df.where("date_key = 20261016").first()  # 16 Oct 2026 is a Friday
    assert row["full_date"] == date(2026, 10, 16)
    assert (row["year"], row["quarter"], row["month"], row["day"]) == (2026, 4, 10, 16)
    assert (row["day_of_week"], row["day_name"], row["is_weekend"]) == (5, "Friday", False)
    assert row["year_month"] == "2026-10" and row["month_name"] == "October"
    sunday = df.where("date_key = 20261018").first()
    assert (sunday["day_of_week"], sunday["is_weekend"]) == (7, True)
    assert df.select("date_key").distinct().count() == 365


def test_dim_date_default_range_size(spark):
    df = build_dim_date(spark, batch_id="b", load_timestamp=TS)
    first, last = df.agg(F.min("full_date"), F.max("full_date")).first()
    assert (first, last) == (date(1988, 1, 1), date(2030, 12, 31))
    assert df.count() == 15706


def test_dim_severity_rows(spark):
    df = build_dim_severity(spark, batch_id="b", load_timestamp=TS)
    assert df.schema == DIM_SEVERITY_SCHEMA
    rows = df.orderBy("sort_order").collect()
    assert [r["severity"] for r in rows] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]
    assert rows[0]["score_min"] == 9.0 and rows[-1]["score_min"] is None
    assert all(r["batch_id"] == "b" for r in rows)
