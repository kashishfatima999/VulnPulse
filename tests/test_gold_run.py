"""Gold incremental scope: changed CVE set, scoping, next watermark."""

from datetime import datetime, timezone

import pytest

from vulnpulse.gold.run import changed_cve_ids, max_load_timestamp, scope_to

pytestmark = pytest.mark.spark
UTC = timezone.utc


def ts(*a):
    return datetime(*a, tzinfo=UTC)


@pytest.fixture(scope="module")
def frames(spark):
    cve = spark.createDataFrame(
        [("CVE-1", "x", ts(2026, 10, 1, 10)), ("CVE-2", "y", ts(2026, 10, 5, 10)), ("CVE-3", "z", ts(2026, 10, 9, 10))],
        ["cve_id", "attr", "load_timestamp"],
    )  # fmt: skip
    kev = spark.createDataFrame(
        [("CVE-1", ts(2026, 10, 8, 12))],  # KEV row for an old CVE arrived later
        ["cve_id", "load_timestamp"],
    )
    return cve, kev


def test_changed_ids_union_across_tables(frames):
    cve, kev = frames
    changed = changed_cve_ids([cve, kev], since=ts(2026, 10, 6))
    assert sorted(r["cve_id"] for r in changed.collect()) == ["CVE-1", "CVE-3"]
    # CVE-1's own row is old, but its KEV row is new, so its fact must be rebuilt


def test_changed_ids_none_means_everything(frames):
    cve, kev = frames
    assert changed_cve_ids([cve, kev], since=None).count() == 3


def test_changed_ids_strictly_after_watermark(frames):
    cve, kev = frames
    assert changed_cve_ids([cve], since=ts(2026, 10, 9, 10)).count() == 0


def test_scope_to_filters_and_passthrough(frames):
    cve, kev = frames
    ids = changed_cve_ids([kev], since=None)
    assert [r["cve_id"] for r in scope_to(cve, ids).collect()] == ["CVE-1"]
    assert scope_to(cve, None).count() == 3


def test_max_load_timestamp(frames, spark):
    cve, kev = frames
    assert max_load_timestamp([cve, kev]) == ts(2026, 10, 9, 10)
    empty = spark.createDataFrame([], "cve_id string, load_timestamp timestamp")
    assert max_load_timestamp([empty]) is None
