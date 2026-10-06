#!/usr/bin/env python3
"""
Validate the Phase 1 sample payloads in data/.

Checks that every artifact listed in data/source_manifest.json
  1. exists,
  2. is valid JSON,
  3. has a SHA-256 digest equal to the one recorded in the manifest,
  4. contains the number of records the manifest says it does.

Exit code 0 on success, 1 on any failure. Used by CI and runnable locally:

    python scripts/validate_samples.py
"""

import hashlib
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
MANIFEST_PATH = DATA_DIR / "source_manifest.json"


def sha256_of(path: Path) -> str:
    hasher = hashlib.sha256()
    with open(path, "rb") as fp:
        while chunk := fp.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def main() -> int:
    if not MANIFEST_PATH.exists():
        print(f"FAIL  missing manifest: {MANIFEST_PATH}")
        return 1

    with open(MANIFEST_PATH, encoding="utf-8") as fp:
        manifest = json.load(fp)

    artifacts = manifest.get("artifacts", {})
    if not artifacts:
        print("FAIL  manifest lists no artifacts")
        return 1

    failures = 0
    for name, meta in artifacts.items():
        path = DATA_DIR / meta["file"]

        if not path.exists():
            print(f"FAIL  {name}: file not found ({path.name})")
            failures += 1
            continue

        try:
            with open(path, encoding="utf-8") as fp:
                payload = json.load(fp)
        except json.JSONDecodeError as exc:
            print(f"FAIL  {name}: invalid JSON ({exc})")
            failures += 1
            continue

        actual_sha = sha256_of(path)
        if actual_sha != meta["sha256"]:
            print(f"FAIL  {name}: SHA-256 mismatch")
            print(f"        expected {meta['sha256']}")
            print(f"        actual   {actual_sha}")
            failures += 1
            continue

        actual_count = len(payload.get("vulnerabilities", []))
        if actual_count != meta["record_count"]:
            print(f"FAIL  {name}: expected {meta['record_count']} records, found {actual_count}")
            failures += 1
            continue

        print(f"OK    {name}: {actual_count} records, sha256 {actual_sha[:12]}...")

    if failures:
        print(f"\n{failures} artifact(s) failed validation.")
        return 1

    print("\nAll sample artifacts match source_manifest.json.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
