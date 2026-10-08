"""NVD CVE API 2.0 client for incremental and backfill windows.

Fetches every page of CVEs whose ``lastModified`` falls inside ``[start, end)`` and writes each
page as one JSON file into a landing directory. Bronze then reads that directory with the same
explicit schema it uses for yearly feeds, so FULL, INCREMENTAL and BACKFILL share one read path.

API facts this module encodes (https://nvd.nist.gov/developers/vulnerabilities):

* ``lastModStartDate`` and ``lastModEndDate`` must both be given, ISO-8601, max 120 days apart.
* ``resultsPerPage`` caps at 2000; pagination is by ``startIndex``.
* Rate limit: 5 requests per rolling 30 s without an API key, 50 with one. We sleep between pages.
* Transient 403/503 responses happen under load; we retry with exponential backoff.

Everything that touches the network or the clock is injectable (``fetch_json``, ``sleep``) so the
pagination and chunking logic is unit-tested without an internet connection.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MAX_WINDOW_DAYS = 120
RESULTS_PER_PAGE = 2000
PAUSE_WITHOUT_KEY_SECONDS = 6.5
PAUSE_WITH_KEY_SECONDS = 0.7

FetchJson = Callable[[str, str | None], dict]


def format_nvd_timestamp(ts: datetime) -> str:
    """``2026-09-24T00:00:00.000`` in UTC, the exact shape the API accepts."""
    if ts.tzinfo is not None:
        ts = ts.astimezone(timezone.utc)
    return ts.strftime("%Y-%m-%dT%H:%M:%S.000")


def split_window(
    start: datetime, end: datetime, max_days: int = MAX_WINDOW_DAYS
) -> list[tuple[datetime, datetime]]:
    """Cut ``[start, end)`` into consecutive chunks no longer than the API allows."""
    if end <= start:
        raise ValueError(f"end must be after start, got start={start} end={end}")
    chunks: list[tuple[datetime, datetime]] = []
    cursor = start
    while cursor < end:
        nxt = min(cursor + timedelta(days=max_days), end)
        chunks.append((cursor, nxt))
        cursor = nxt
    return chunks


def build_page_url(
    start: datetime,
    end: datetime,
    start_index: int,
    results_per_page: int = RESULTS_PER_PAGE,
    base_url: str = NVD_API_URL,
) -> str:
    query = {
        "lastModStartDate": format_nvd_timestamp(start),
        "lastModEndDate": format_nvd_timestamp(end),
        "resultsPerPage": results_per_page,
        "startIndex": start_index,
    }
    return f"{base_url}?{urllib.parse.urlencode(query)}"


def default_fetch_json(url: str, api_key: str | None = None, timeout: int = 90) -> dict:
    headers = {"User-Agent": "VulnPulse/0.2 (university project)"}
    if api_key:
        headers["apiKey"] = api_key
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def fetch_with_retry(
    url: str,
    *,
    fetch_json: FetchJson = default_fetch_json,
    api_key: str | None = None,
    retries: int = 4,
    backoff_seconds: float = 5.0,
    sleep: Callable[[float], None] = time.sleep,
) -> dict:
    """Call ``fetch_json`` and retry transient failures with exponential backoff."""
    attempt = 0
    while True:
        try:
            return fetch_json(url, api_key)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
            if attempt >= retries:
                raise
            sleep(backoff_seconds * (2**attempt))
            attempt += 1


@dataclass
class FetchResult:
    files: list[str] = field(default_factory=list)
    pages: int = 0
    records: int = 0
    total_results: int = 0
    requests: int = 0


def fetch_window_to_files(
    start: datetime,
    end: datetime,
    out_dir: str,
    *,
    api_key: str | None = None,
    fetch_json: FetchJson = default_fetch_json,
    sleep: Callable[[float], None] = time.sleep,
    results_per_page: int = RESULTS_PER_PAGE,
) -> FetchResult:
    """Download every page for the window into ``out_dir`` as ``page_00000.json``, ``page_00001.json``..."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    pause = PAUSE_WITH_KEY_SECONDS if api_key else PAUSE_WITHOUT_KEY_SECONDS
    result = FetchResult()

    for chunk_start, chunk_end in split_window(start, end):
        start_index = 0
        chunk_total: int | None = None
        while True:
            url = build_page_url(chunk_start, chunk_end, start_index, results_per_page)
            page = fetch_with_retry(url, fetch_json=fetch_json, api_key=api_key, sleep=sleep)
            result.requests += 1

            if chunk_total is None:
                chunk_total = int(page.get("totalResults", 0))
                result.total_results += chunk_total

            records = page.get("vulnerabilities", [])
            if records:
                path = out / f"page_{result.pages:05d}.json"
                path.write_text(json.dumps(page), encoding="utf-8")
                result.files.append(str(path))
                result.pages += 1
                result.records += len(records)

            start_index += results_per_page
            if start_index >= chunk_total or not records:
                break
            sleep(pause)

    return result
