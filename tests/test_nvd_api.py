"""NVD API client tests. No network: fetch_json and sleep are injected fakes."""

import json
import urllib.error
from datetime import datetime, timedelta, timezone

import pytest

from vulnpulse.ingestion.nvd_api import (
    build_page_url,
    fetch_window_to_files,
    fetch_with_retry,
    format_nvd_timestamp,
    split_window,
)

UTC = timezone.utc
T0 = datetime(2026, 1, 1, tzinfo=UTC)


def test_timestamp_format_is_what_nvd_accepts():
    ts = datetime(2026, 9, 24, 15, 38, 4, 713000, tzinfo=UTC)
    assert format_nvd_timestamp(ts) == "2026-09-24T15:38:04.000"
    # Non-UTC input is converted, not just relabelled.
    plus5 = datetime(2026, 9, 24, 20, 38, 4, tzinfo=timezone(timedelta(hours=5)))
    assert format_nvd_timestamp(plus5) == "2026-09-24T15:38:04.000"


def test_split_window_respects_120_day_limit():
    chunks = split_window(T0, T0 + timedelta(days=300))
    assert len(chunks) == 3
    assert chunks[0] == (T0, T0 + timedelta(days=120))
    assert chunks[-1][1] == T0 + timedelta(days=300)
    assert all((b - a).days <= 120 for a, b in chunks)
    assert split_window(T0, T0 + timedelta(hours=1)) == [(T0, T0 + timedelta(hours=1))]
    with pytest.raises(ValueError):
        split_window(T0, T0)


def test_build_page_url():
    url = build_page_url(T0, T0 + timedelta(days=1), 4000)
    assert url.startswith("https://services.nvd.nist.gov/rest/json/cves/2.0?")
    assert "lastModStartDate=2026-01-01T00%3A00%3A00.000" in url
    assert "lastModEndDate=2026-01-02T00%3A00%3A00.000" in url
    assert "resultsPerPage=2000" in url and "startIndex=4000" in url


def _fake_api(total, per_page):
    """Return a fetch_json fake serving `total` records in pages of `per_page`."""
    calls = []

    def fetch(url, api_key):
        calls.append((url, api_key))
        start = int(url.split("startIndex=")[1])
        ids = range(start, min(start + per_page, total))
        return {
            "resultsPerPage": per_page,
            "startIndex": start,
            "totalResults": total,
            "format": "NVD_CVE",
            "version": "2.0",
            "timestamp": "2026-01-01T00:00:00.000",
            "vulnerabilities": [{"cve": {"id": f"CVE-2026-{i:04d}"}} for i in ids],
        }

    return fetch, calls


def test_fetch_window_paginates_and_writes_pages(tmp_path):
    fetch, calls = _fake_api(total=5, per_page=2)
    sleeps = []
    result = fetch_window_to_files(
        T0,
        T0 + timedelta(days=1),
        str(tmp_path),
        fetch_json=fetch,
        sleep=sleeps.append,
        results_per_page=2,
    )
    assert result.pages == 3 and result.records == 5 and result.total_results == 5
    assert result.requests == 3
    assert [p.name for p in sorted(tmp_path.iterdir())] == [
        "page_00000.json",
        "page_00001.json",
        "page_00002.json",
    ]
    written = [json.loads(p.read_text())["vulnerabilities"] for p in sorted(tmp_path.iterdir())]
    assert [len(w) for w in written] == [2, 2, 1]
    assert len(sleeps) == 2  # pause between pages, none after the last
    assert all(key is None for _, key in calls)


def test_fetch_window_handles_empty_window(tmp_path):
    fetch, calls = _fake_api(total=0, per_page=2000)
    result = fetch_window_to_files(T0, T0 + timedelta(hours=1), str(tmp_path), fetch_json=fetch)
    assert result.pages == 0 and result.records == 0 and result.requests == 1
    assert list(tmp_path.iterdir()) == []


def test_fetch_window_passes_api_key_and_splits_long_windows(tmp_path):
    fetch, calls = _fake_api(total=1, per_page=2000)
    result = fetch_window_to_files(
        T0,
        T0 + timedelta(days=250),
        str(tmp_path),
        api_key="k",
        fetch_json=fetch,
        sleep=lambda s: None,
    )
    assert result.requests == 3  # three chunks of <=120 days, one page each
    assert all(key == "k" for _, key in calls)


def test_fetch_with_retry_recovers_from_transient_errors():
    attempts = {"n": 0}

    def flaky(url, api_key):
        attempts["n"] += 1
        if attempts["n"] < 3:
            raise urllib.error.URLError("503")
        return {"ok": True}

    sleeps = []
    assert fetch_with_retry("u", fetch_json=flaky, sleep=sleeps.append) == {"ok": True}
    assert attempts["n"] == 3
    assert sleeps == [5.0, 10.0]  # exponential backoff


def test_fetch_with_retry_gives_up():
    def always_fails(url, api_key):
        raise urllib.error.URLError("down")

    with pytest.raises(urllib.error.URLError):
        fetch_with_retry("u", fetch_json=always_fails, retries=2, sleep=lambda s: None)
