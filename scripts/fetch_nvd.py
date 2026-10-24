#!/usr/bin/env python3
"""
Fetch NVD CVE API pages for a time window into a local landing folder.

Runs on your laptop (Databricks Free Edition cannot reach the internet). Afterwards upload the
printed folder to the Unity Catalog volume and run notebooks/01_bronze_nvd.py pointing at it.

Examples
    # standard daily incremental: everything modified in the last 24 hours
    python scripts/fetch_nvd.py

    # incremental from the last watermark (printed by the notebook as "next fetch")
    python scripts/fetch_nvd.py --start 2026-10-08T13:10:00

    # backfill a historical window (max 120 days per request; longer windows are chunked)
    python scripts/fetch_nvd.py --start 2026-10-01T00:00:00 --end 2026-10-02T00:00:00

Set NVD_API_KEY in the environment for the 10x rate limit. The key is never written anywhere.

How this differs from scripts/fetch_kev.py:
    * This script takes a TIME WINDOW (--start / --end / --hours) and the window decides the load
      type: INCREMENTAL or BACKFILL. fetch_kev.py takes no window at all; it always downloads the
      whole catalog and the load type is always FULL.
    * This script PAGES: the API caps a response at 2,000 records, so a window becomes N requests
      (startIndex 0, 2000, 4000, ...) and N files (page_000.json, page_001.json, ...), with a pause
      between pages for the rate limit. fetch_kev.py makes one request and writes one file.
    * Both write manifest.json next to the data, with the same core keys (load_type, batch_id,
      fetched_at, source_uri, records). This one adds window_start/window_end/pages/requests/
      total_results; the KEV one adds catalog_version.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import timezone
from pathlib import Path

# The script lives in scripts/, the package in src/. Put src on the import path so the script
# reuses the same vulnpulse code the notebooks and tests use (no copy-pasted logic).
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

# noqa: E402 = "import not at top of file". Deliberate: the sys.path line above must run first.
from vulnpulse.ingestion import nvd_api  # noqa: E402
from vulnpulse.ingestion.landing import resolve_window, write_manifest  # noqa: E402
from vulnpulse.utils.params import new_batch_id, utc_now  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    # The three window flags. Their combination picks the load type (see resolve_window):
    #   --start alone        -> INCREMENTAL from start to now (start = watermark - 10 min)
    #   --start and --end    -> BACKFILL of exactly [start, end)
    #   neither              -> INCREMENTAL over the last --hours (default 24)
    parser.add_argument(
        "--start", help="ISO-8601 UTC. Alone: incremental from here. With --end: backfill."
    )
    parser.add_argument("--end", help="ISO-8601 UTC. Makes this a BACKFILL; requires --start.")
    parser.add_argument(
        "--hours", type=float, default=24, help="Incremental lookback when --start is absent."
    )
    parser.add_argument("--out", default="landing", help="Local landing root (git-ignored).")
    parser.add_argument("--batch-id", default="", help="Reuse a batch id; default: new one.")
    args = parser.parse_args(argv)

    now = utc_now()
    # resolve_window (src/vulnpulse/ingestion/landing.py) turns the flags into
    # (load_type, start, end) and rejects an empty or inverted window. This is the only place
    # where "is this a backfill or an incremental?" is decided.
    load_type, start, end = resolve_window(args.start, args.end, args.hours, now)
    # batch_id is minted here, on the laptop, e.g. 20261016T202804Z-dbece997 (UTC time + 8 hex).
    # It becomes the landing folder name, goes into the manifest, and the notebook stamps it on
    # every Bronze row. That is how a Bronze row traces back to this exact run.
    batch_id = args.batch_id.strip() or new_batch_id()
    out_dir = Path(args.out) / "nvd" / batch_id
    # The API key is read from the environment only. It is never printed, never written to the
    # manifest, never in Git. With a key NVD allows 50 requests / 30 s; without, 5 / 30 s.
    api_key = os.environ.get("NVD_API_KEY") or None

    print(f"{load_type}: {start.isoformat()} -> {end.isoformat()}")
    print(f"batch_id: {batch_id}")
    print(
        f"api key:  {'NVD_API_KEY from environment' if api_key else 'none (public rate limit, ~7 s between pages)'}"
    )
    print(f"writing:  {out_dir}")

    # The paging loop (src/vulnpulse/ingestion/nvd_api.py):
    #   1. split_window chunks the window into <=120-day pieces (an NVD API limit).
    #   2. For each piece, request startIndex 0, 2000, 4000, ... until startIndex >= totalResults.
    #   3. Each response is written as its own page_NNN.json, exactly as received.
    #   4. fetch_with_retry backs off 5/10/20/40 s on 429 / 5xx / timeouts.
    #   5. A pause between pages respects the rate limit.
    # KEV has none of this: one request, one file.
    result = nvd_api.fetch_window_to_files(start, end, str(out_dir), api_key=api_key)

    # manifest.json: the run's description, written next to the data. The notebook reads it to
    # learn the window, load type, batch id and source URL, so none of that is typed by hand in
    # Databricks (the start_date / end_date widgets stay blank). The notebook also copies the
    # manifest into the parameters column of pipeline_execution_logs, so it survives after the
    # landing folder is purged.
    write_manifest(
        str(out_dir),
        source="nvd_cve_api",
        load_type=load_type,
        batch_id=batch_id,
        window_start=start,  # NVD-only: KEV has no window
        window_end=end,  # NVD-only
        fetched_at=utc_now(),
        source_uri=nvd_api.build_page_url(start, end, 0),  # first page URL = provenance
        records=result.records,  # 0 is valid: an empty window still advances the watermark
        pages=result.pages,  # NVD-only: number of page files written
        requests=result.requests,  # NVD-only: includes retries
        total_results=result.total_results,  # NVD-only: what the API said the window holds
    )

    print(
        f"fetched:  {result.records} records in {result.pages} page(s), {result.requests} request(s)"
    )
    print()
    # Hand-off instructions: the folder must be uploaded to the volume under the same batch_id
    # so the folder name, manifest and Bronze rows all agree.
    print("Next steps")
    print(
        f"  1. Databricks > Catalog > workspace > vulnpulse_bronze > landing > create folder nvd/{batch_id}"
    )
    print(f"     and upload every file from {out_dir} into it (page_*.json and manifest.json).")
    print("  2. Run notebooks/01_bronze_nvd.py with")
    print(f"       load_type   = {load_type}")
    print(f"       source_path = /Volumes/workspace/vulnpulse_bronze/landing/nvd/{batch_id}")
    print(f"       batch_id    = {batch_id}")
    print(f"     (now is {now.astimezone(timezone.utc).isoformat()})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
