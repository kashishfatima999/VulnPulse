#!/usr/bin/env python3
"""
Download the CISA KEV catalog into a local landing folder (laptop side).

    python scripts/fetch_kev.py

Then upload the printed folder to the volume and run notebooks/02_bronze_kev.py pointing at it.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from vulnpulse.bronze.kev import KEV_URL, download_catalog  # noqa: E402
from vulnpulse.ingestion.landing import write_manifest  # noqa: E402
from vulnpulse.utils.params import new_batch_id, utc_now  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", default="landing", help="Local landing root (git-ignored).")
    parser.add_argument("--batch-id", default="")
    args = parser.parse_args(argv)

    batch_id = args.batch_id.strip() or new_batch_id()
    out_dir = Path(args.out) / "kev" / batch_id
    path = download_catalog(str(out_dir / "known_exploited_vulnerabilities.json"))
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    count = len(payload.get("vulnerabilities", []))

    write_manifest(
        str(out_dir),
        source="cisa_kev",
        load_type="FULL",
        batch_id=batch_id,
        fetched_at=utc_now(),
        source_uri=KEV_URL,
        catalog_version=payload.get("catalogVersion"),
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
