#!/usr/bin/env python3
"""
Download the CISA KEV catalog into a local landing folder (laptop side).

    python scripts/fetch_kev.py

Then upload the printed folder to the volume and run notebooks/02_bronze_kev.py pointing at it.

How this differs from scripts/fetch_nvd.py:
    * No --start / --end / --hours. CISA offers no "modified since" filter, only the whole
      catalog as one file (about 1,700 entries, a few hundred KB). So every fetch is the whole
      thing and the load type is hard-coded FULL. There is no watermark for KEV.
    * No paging. One HTTP request, one file. fetch_nvd.py loops over startIndex in steps of
      2,000 and writes one file per page.
    * The manifest records catalog_version (CISA's own version stamp, e.g. 2026.10.16) instead of
      a time window. That is how two KEV snapshots are told apart.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

# The script lives in scripts/, the package in src/. Put src on the import path so the script
# reuses the same vulnpulse code the notebooks and tests use.
REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

# noqa: E402 = "import not at top of file". Deliberate: the sys.path line above must run first.
from vulnpulse.bronze.kev import KEV_URL, download_catalog  # noqa: E402
from vulnpulse.ingestion.landing import write_manifest  # noqa: E402
from vulnpulse.utils.params import new_batch_id, utc_now  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    # Only two flags, both optional. Compare fetch_nvd.py, which needs the window flags.
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="landing", help="Local landing root (git-ignored).")
    parser.add_argument("--batch-id", default="")
    args = parser.parse_args(argv)

    # batch_id minted here, same format as NVD (UTC time + 8 hex). Folder name, manifest and
    # every Bronze row share it.
    batch_id = args.batch_id.strip() or new_batch_id()
    out_dir = Path(args.out) / "kev" / batch_id
    # One request with retry/backoff (shared fetch_with_retry), written verbatim to one file.
    path = download_catalog(str(out_dir / "known_exploited_vulnerabilities.json"))
    # Re-read the file only to count entries and read the version for the manifest.
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    count = len(payload.get("vulnerabilities", []))

    # manifest.json: same idea as NVD (notebook reads it instead of hand-typed widgets), but with
    # catalog_version instead of window_start/window_end, and always load_type FULL.
    write_manifest(
        str(out_dir),
        source="cisa_kev",
        load_type="FULL",  # always; KEV cannot be incremental
        batch_id=batch_id,
        fetched_at=utc_now(),
        source_uri=KEV_URL,
        catalog_version=payload.get("catalogVersion"),  # KEV-only: CISA's snapshot version
        records=count,
    )
    print(f"downloaded {count} KEV entries, catalog {payload.get('catalogVersion')}, to {out_dir}")
    print()
    print("Next steps")
    print(
        f"  1. Upload both files from {out_dir} to /Volumes/workspace/vulnpulse_bronze/landing/kev/{batch_id}"
    )
    print("  2. Run notebooks/02_bronze_kev.py with")
    print(f"       source_path = /Volumes/workspace/vulnpulse_bronze/landing/kev/{batch_id}")
    print(f"       batch_id    = {batch_id}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
