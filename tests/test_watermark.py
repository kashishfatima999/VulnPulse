"""Watermark window logic (pure) and table schema."""

from datetime import datetime, timedelta, timezone

import pytest

from vulnpulse.utils.watermark import WATERMARK_SCHEMA, incremental_window

UTC = timezone.utc
NOW = datetime(2026, 10, 9, 12, 0, tzinfo=UTC)


def test_known_watermark_minus_overlap():
    wm = datetime(2026, 10, 9, 9, 0, tzinfo=UTC)
    start, end = incremental_window(wm, NOW)
    assert start == wm - timedelta(minutes=10)
    assert end == NOW


def test_first_run_uses_seed_when_given():
    seed = datetime(2026, 10, 1, tzinfo=UTC)
    assert incremental_window(None, NOW, seed_start=seed) == (seed, NOW)


def test_first_run_without_seed_looks_back_one_day():
    start, end = incremental_window(None, NOW)
    assert start == NOW - timedelta(days=1) and end == NOW


def test_watermark_wins_over_seed():
    wm = datetime(2026, 10, 9, 9, 0, tzinfo=UTC)
    seed = datetime(2026, 10, 1, tzinfo=UTC)
    start, _ = incremental_window(wm, NOW, seed_start=seed)
    assert start == wm - timedelta(minutes=10)


def test_empty_window_is_rejected():
    # A watermark in the future (clock skew, bad manual edit) must not produce an inverted window.
    with pytest.raises(ValueError):
        incremental_window(NOW + timedelta(hours=1), NOW)


def test_schema_has_required_columns():
    assert [f.name for f in WATERMARK_SCHEMA.fields] == [
        "source",
        "watermark_ts",
        "batch_id",
        "load_timestamp",
    ]
