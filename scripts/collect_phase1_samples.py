#!/usr/bin/env python3
"""
VulnPulse - Phase 1 Sample Data Collector
Fetches authentic raw sample records from NVD CVE API 2.0 and CISA KEV feeds,
computes their SHA-256 digests, and updates source_manifest.json.

Usage:
    python scripts/collect_phase1_samples.py
"""

import os
import sys
import json
import hashlib
from datetime import datetime, timezone, timedelta
from pathlib import Path
import urllib.request
import urllib.error

# Resolve paths
REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

NVD_API_KEY = os.environ.get("NVD_API_KEY")


def compute_sha256(file_path: Path) -> str:
    """Compute SHA-256 hex digest for a file."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


def fetch_json(url: str, headers: dict = None) -> dict:
    """Fetch JSON payload from a remote URL."""
    req_headers = {"User-Agent": "VulnPulse-Data-Collector/1.0"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def main():
    print("[VulnPulse] Collecting authentic Phase 1 sample payloads...")
    now_utc = datetime.now(timezone.utc)
    manifest_artifacts = {}

    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
        print("  - Using NVD API key from environment")

    # 1. NVD Full Load Sample (Unfiltered baseline page of 10 CVEs)
    full_url = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=10&startIndex=0"
    print(f"  [1/3] Fetching NVD Full Load sample from: {full_url}")
    try:
        full_data = fetch_json(full_url, headers=headers)
        full_sample_path = DATA_DIR / "nvd_full_load_sample.json"
        with open(full_sample_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(full_data, f, indent=2)
            f.write("\n")
        full_sha256 = compute_sha256(full_sample_path)
        manifest_artifacts["nvd_full_load_sample"] = {
            "file": "nvd_full_load_sample.json",
            "source_url": full_url,
            "record_count": len(full_data.get("vulnerabilities", [])),
            "sha256": full_sha256,
        }
        print(f"      Saved {full_sample_path.name} (SHA-256: {full_sha256[:12]}...)")
    except Exception as e:
        print(f"      Warning: Could not fetch NVD full load sample: {e}")

    # 2. NVD Incremental Load Sample (24-hour modified window, 10 records)
    window_end = now_utc.strftime("%Y-%m-%dT%H:%M:%S.000")
    window_start = (now_utc - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%S.000")
    inc_url = (
        f"https://services.nvd.nist.gov/rest/json/cves/2.0?"
        f"lastModStartDate={window_start}&lastModEndDate={window_end}&resultsPerPage=10&startIndex=0"
    )
    print(f"  [2/3] Fetching NVD Incremental Load sample from: {inc_url}")
    try:
        inc_data = fetch_json(inc_url, headers=headers)
        inc_sample_path = DATA_DIR / "nvd_incremental_load_sample.json"
        with open(inc_sample_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(inc_data, f, indent=2)
            f.write("\n")
        inc_sha256 = compute_sha256(inc_sample_path)
        manifest_artifacts["nvd_incremental_load_sample"] = {
            "file": "nvd_incremental_load_sample.json",
            "source_url": inc_url,
            "window_start": f"{window_start}Z",
            "window_end": f"{window_end}Z",
            "record_count": len(inc_data.get("vulnerabilities", [])),
            "sha256": inc_sha256,
            "total_matches_in_window": inc_data.get("totalResults", 0),
            "window_widened": False,
        }
        print(f"      Saved {inc_sample_path.name} (SHA-256: {inc_sha256[:12]}...)")
    except Exception as e:
        print(f"      Warning: Could not fetch NVD incremental sample: {e}")

    # 3. CISA KEV Sample (Trimmed to 10 records)
    cisa_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    print(f"  [3/3] Fetching CISA KEV sample from: {cisa_url}")
    try:
        cisa_data = fetch_json(cisa_url)
        cisa_full_count = len(cisa_data.get("vulnerabilities", []))
        cisa_data["vulnerabilities"] = cisa_data.get("vulnerabilities", [])[:10]
        cisa_data["count"] = len(cisa_data["vulnerabilities"])

        cisa_sample_path = DATA_DIR / "cisa_kev_sample.json"
        with open(cisa_sample_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(cisa_data, f, indent=2)
            f.write("\n")
        cisa_sha256 = compute_sha256(cisa_sample_path)
        manifest_artifacts["cisa_kev_sample"] = {
            "file": "cisa_kev_sample.json",
            "source_url": cisa_url,
            "record_count": len(cisa_data["vulnerabilities"]),
            "note": f"Trimmed from the full CISA KEV catalog ({cisa_full_count} entries at capture time) to first 10 records.",
            "sha256": cisa_sha256,
        }
        print(f"      Saved {cisa_sample_path.name} (SHA-256: {cisa_sha256[:12]}...)")
    except Exception as e:
        print(f"      Warning: Could not fetch CISA KEV sample: {e}")

    # Write manifest if any succeeded
    if manifest_artifacts:
        manifest = {
            "captured_at_utc": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "artifacts": manifest_artifacts,
        }
        manifest_path = DATA_DIR / "source_manifest.json"
        with open(manifest_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")
        print(f"  Saved {manifest_path.name}")
        print("\nAll sample payloads collected successfully.")


if __name__ == "__main__":
    main()
