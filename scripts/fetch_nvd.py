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
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnpulse.ingestion import nvd_api  # noqa: E402
from vulnpulse.ingestion.landing import resolve_window, write_manifest  # noqa: E402
from vulnpulse.utils.params import new_batch_id, utc_now  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
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
    load_type, start, end = resolve_window(args.start, args.end, args.hours, now)
    batch_id = args.batch_id.strip() or new_batch_id()
    out_dir = Path(args.out) / "nvd" / batch_id
    api_key = os.environ.get("NVD_API_KEY") or None

    print(f"{load_type}: {start.isoformat()} -> {end.isoformat()}")
    print(f"batch_id: {batch_id}")
    print(
        f"api key:  {'NVD_API_KEY from environment' if api_key else 'none (public rate limit, ~7 s between pages)'}"
    )
    print(f"writing:  {out_dir}")

    result = nvd_api.fetch_window_to_files(start, end, str(out_dir), api_key=api_key)

    write_manifest(
        str(out_dir),
        source="nvd_cve_api",
        load_type=load_type,
        batch_id=batch_id,
        window_start=start,
        window_end=end,
        fetched_at=utc_now(),
        source_uri=nvd_api.build_page_url(start, end, 0),
        records=result.records,
        pages=result.pages,
        requests=result.requests,
        total_results=result.total_results,
    )

    print(
        f"fetched:  {result.records} records in {result.pages} page(s), {result.requests} request(s)"
    )
    print()
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
