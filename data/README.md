# Sample Data

Small, real evidence samples for the VulnPulse Phase 1 proposal. These are excerpts pulled directly from the live NVD and CISA sources, not fabricated data.

## Files

| File | Contents | Records | Source |
|---|---|---|---|
| `nvd_full_load_sample.json` | An unfiltered page of CVE records, representing the shape of a "full load" pull | 10 | NVD CVE API 2.0 |
| `nvd_incremental_load_sample.json` | CVEs modified within a specific 24-hour window, representing the incremental (watermark) pattern | 10 | NVD CVE API 2.0, `lastModStartDate`/`lastModEndDate` filter |
| `cisa_kev_sample.json` | The first 10 entries from the current CISA Known Exploited Vulnerabilities catalog | 10 | CISA KEV JSON feed |
| `source_manifest.json` | Exact source URLs, capture timestamp, record counts, and SHA-256 hashes for the three files above | - | - |

## Why these are small

Per the project's storage guardrails (see the Phase 1 proposal, Sections 5 and 9), full feeds are never committed to this repository:

- The full NVD yearly feeds run to ~130+ MiB compressed.
- The full CISA KEV catalog currently holds 1,700+ entries.

These samples exist only to demonstrate the shape of both load patterns and to satisfy the Phase 1 requirement for real sample payloads. The actual pipeline (Phase 2+) will pull full/incremental data directly from the live sources rather than reading from this folder.

## Provenance

`source_manifest.json` records exactly when and how each file was captured, including the exact request URL and a SHA-256 hash of the file contents, so the samples are independently verifiable against the live NVD/CISA APIs at any time.

## Regenerating these samples

Either:
- Run `python scripts/collect_phase1_samples.py` (an `NVD_API_KEY` environment variable is optional but recommended to avoid rate limiting), or
- Query the endpoints manually and trim the results to a handful of records — see `source_manifest.json` for the exact URLs used.

## Official Resources

- NIST NVD CVE API 2.0: https://services.nvd.nist.gov/rest/json/cves/2.0
- NIST NVD Yearly Feeds: https://nvd.nist.gov/feeds/json/cve/2.0
- CISA Known Exploited Vulnerabilities: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CISA KEV JSON Feed: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

## PII Note

No personal data is intentionally retained. NVD's `sourceIdentifier` field can occasionally contain email-like source-attribution values; per the proposal's Section 6, this field is dropped in Silver/Gold and is not treated as project data.
