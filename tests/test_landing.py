"""Landing manifest round-trip and CLI window resolution."""

from datetime import datetime, timedelta, timezone

import pytest

from vulnpulse.ingestion.landing import parse_utc, read_manifest, resolve_window, write_manifest

UTC = timezone.utc
NOW = datetime(2026, 10, 8, 15, 0, tzinfo=UTC)


def test_default_is_incremental_last_24h():
    load_type, start, end = resolve_window(None, None, None, NOW)
    assert load_type == "INCREMENTAL"
    assert (start, end) == (NOW - timedelta(hours=24), NOW)


def test_hours_override():
    _, start, end = resolve_window(None, None, 6, NOW)
    assert (start, end) == (NOW - timedelta(hours=6), NOW)


def test_start_alone_is_incremental_from_watermark():
    load_type, start, end = resolve_window("2026-10-08T13:10:00", None, None, NOW)
    assert load_type == "INCREMENTAL"
    assert start == datetime(2026, 10, 8, 13, 10, tzinfo=UTC) and end == NOW


def test_start_and_end_is_backfill():
    load_type, start, end = resolve_window("2026-10-01", "2026-10-02T00:00:00Z", None, NOW)
    assert load_type == "BACKFILL"
    assert start == datetime(2026, 10, 1, tzinfo=UTC) and end == datetime(2026, 10, 2, tzinfo=UTC)


def test_end_without_start_rejected():
    with pytest.raises(ValueError):
        resolve_window(None, "2026-10-02", None, NOW)


def test_empty_window_rejected():
    with pytest.raises(ValueError):
        resolve_window("2026-10-09", None, None, NOW)


def test_parse_utc_converts_offsets():
    assert parse_utc("2026-10-08T20:00:00+05:00") == datetime(2026, 10, 8, 15, 0, tzinfo=UTC)
    assert parse_utc("2026-10-08").tzinfo is UTC


def test_manifest_round_trip(tmp_path):
    path = write_manifest(
        str(tmp_path), source="nvd_cve_api", load_type="BACKFILL", window_start=NOW, records=3
    )
    assert path.endswith("manifest.json")
    m = read_manifest(str(tmp_path))
    assert m["load_type"] == "BACKFILL" and m["records"] == 3
    assert parse_utc(m["window_start"]) == NOW
    assert read_manifest(str(tmp_path / "missing")) is None
    assert read_manifest("file:" + str(tmp_path)) == m
