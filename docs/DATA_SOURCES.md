# VulnPulse Data Sources & Ingestion Specifications

## 1. National Vulnerability Database (NVD)

- **Source Authority:** National Institute of Standards and Technology (NIST)
- **Official Portal:** [https://nvd.nist.gov/](https://nvd.nist.gov/)
- **API Documentation:** [https://nvd.nist.gov/developers/vulnerabilities](https://nvd.nist.gov/developers/vulnerabilities)

### 1.1 Full Baseline Ingestion
- **Feed Type:** Yearly JSON 2.0 archives (`.json.gz`)
- **URL Pattern:** `https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{YEAR}.json.gz`
- **Scope:** 2020 through 2026.
- **Estimated Compressed Size:** ~132 MiB total across the 7-year baseline.
- **Operational Pattern:** Executed once at initial platform commissioning. Raw payloads are landed into the Databricks Unity Catalog Landing Volume, staged to Bronze, and purged from transient local storage.

### 1.2 Incremental Load Ingestion
- **Feed Type:** NVD CVE API 2.0 REST endpoint
- **Endpoint URL:** `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Filtering Mechanism:** `lastModStartDate` and `lastModEndDate` query parameters (ISO-8601 UTC).
- **Pagination:** Supported via `resultsPerPage=2000` and `startIndex=0, 2000, ...`.
- **Watermarking Strategy:**
  - After each successful batch run, the maximum `lastModified` timestamp from ingested records is persisted in `gold_pipeline_audit`.
  - Next incremental query uses `lastModStartDate = (watermark - 10 minutes)` to guarantee zero record loss across clock drifts.
  - Deduping in Silver layer resolves any overlap records by primary key (`cve_id` and latest `last_modified_at`).

---

## 2. CISA Known Exploited Vulnerabilities (KEV)

- **Source Authority:** Cybersecurity and Infrastructure Security Agency (CISA)
- **Catalog Webpage:** [https://www.cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **JSON Feed URL:** [https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json)
- **GitHub Mirror:** [https://github.com/cisagov/kev-data](https://github.com/cisagov/kev-data)

### 2.1 Characteristics & Ingestion
- **Volume:** ~1,700–2,000 vulnerability records (~1.7 MB JSON payload).
- **Ingestion Pattern:** Snapshot refresh. Due to the compact size of the catalog, the entire dataset is ingested and reconciled during batch runs.
- **Enrichment Join:** Joined to NVD records on `cve_id` to flag vulnerabilities exploited in the wild.
