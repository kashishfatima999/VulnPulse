# VulnPulse FinOps, Resource Governance and Security Specification

This document defines resource optimization constraints, operational cost management, and security governance rules for the VulnPulse data engineering pipeline running on Apache Spark (Databricks Free Edition).

---

## 1. FinOps Principles and Free Tier Constraints

The project operates under Databricks Free Edition / Azure for Students limits. The platform provides serverless compute with strict core hour quotas and limited persistent storage.

**Verified constraint (8 Oct 2026): Free Edition serverless has no outbound internet.** DNS for
`services.nvd.nist.gov` and `www.cisa.gov` fails (`gaierror -2`); only PyPI resolves. Consequence: all
source acquisition runs on a laptop (`scripts/fetch_nvd.py`, `scripts/fetch_kev.py`) and the result is
uploaded to the landing volume. Notebooks never call the network. Side benefit: no serverless compute
is spent waiting on the NVD public API, which pauses ~7 s between pages without a key.

### 1.1 Compute Optimization
1. **Incremental Processing vs Full Recomputations:**
   - The historical baseline (2020-2026, ~131.5 MiB compressed) is loaded once during initialization.
   - Subsequent scheduled pipelines strictly query modified CVEs using the NVD API `lastModStartDate` and `lastModEndDate` window.
   - **Cost impact:** Reduces per-batch row processing by over 95%, cutting cluster execution time from minutes to seconds.
2. **Cluster Memory and Driver Protection:**
   - PySpark code must avoid calling `.collect()` or `.toPandas()` on large or unaggregated DataFrames.
   - Transformations (flattening, deduplication, joins) must be executed in distributed Spark SQL/DataFrame operations.
   - Only Gold-level summary tables or filtered watchlist subsets may be exported for visualization.
3. **Partitioning and File Sizing:**
   - Bronze and Silver tables use partition pruning on date fields (`year(published_at)`).
   - Write operations utilize standard Delta compaction to avoid creating hundreds of small files (<1 MB) that exhaust file metadata limits.

### 1.2 Storage Guardrails
1. **Repository Hygiene:**
   - Full JSON feeds, compressed archives, Parquet exports, and Delta logs are strictly excluded from the Git repository via `.gitignore`.
   - The repository hosts only small sample payloads (<100 KB total) for verification and testing.
2. **Landing Volume Pruning:**
   - In Databricks Unity Catalog, raw JSON files written to landing volumes during acquisition are removed after they are successfully appended to `bronze_nvd_raw`.
3. **Storage Target Cap:**
   - Total persistent storage (Delta tables + checkpoint logs) across Bronze, Silver, and Gold is capped at 2.0 GB.
   - Intermediate columns not required for analytics (such as localized translations or non-English descriptions) are dropped at the Silver layer.

---

## 2. Progressive Testing Ladder

To prevent accidental consumption of free compute credits during development and debugging, pipeline execution must follow this sequential progression:

| Level | Dataset Scope | Record Count | Objective |
|---|---|---|---|
| **Level 1** | Local Sample Payloads | 10 records | Validate schema parsing, flattening logic, and null handling. |
| **Level 2** | Single-Year Feed | ~20,000 records (1 year) | Test Delta table creation, partitioning, and aggregation performance. |
| **Level 3** | Incremental Batch | 100-2,000 records | Verify watermark persistence, API pagination, and deduplication logic. |
| **Level 4** | Full Baseline Load | ~150,000+ records (2020-2026) | One-time initial historical load to populate production lakehouse. |

---

## 3. Watermark and State Management

Incremental ingestion requires tracking the high-water mark to ensure exactly-once or at-least-once ingestion with deduplication.

### 3.1 Watermark Query Pattern
1. Read `max(watermark_ts)` for `nvd_cve_api` from `pipeline_watermarks`. If empty (first run), use the `start_date` seed parameter when given, otherwise the last 24 hours.
2. Set `lastModStartDate = watermark_timestamp - INTERVAL 10 MINUTES` (safety buffer for clock drift and in-flight commits).
3. Set `lastModEndDate = CURRENT_TIMESTAMP_UTC`.
4. On the laptop, `scripts/fetch_nvd.py --start <watermark - 10 min>` fetches the paginated pages into `landing/nvd/<batch_id>/` with a `manifest.json` (window, load type, source URL). The folder is uploaded to the landing volume.
5. `01_bronze_nvd.py` with `load_type=INCREMENTAL` reads the manifest, appends the pages to Bronze, and warns if the manifest window starts after the stored watermark (a gap).
6. In Silver, merge incoming records into `silver_cve` using `MERGE INTO` on `cve_id` when `source.last_modified_at > target.last_modified_at`.
7. Only after the Bronze append succeeded, append the new maximum `lastModified` to `pipeline_watermarks`. BACKFILL runs (explicit `start_date`/`end_date`) skip this step and never move the watermark.
8. Delete the landed page files from the volume. Write one row to `pipeline_execution_logs` whether the run succeeded or failed.

---

## 4. Security and PII Governance

### 4.1 Threat and Exposure Analysis
The data processed by VulnPulse consists of public vulnerability registries and exploit catalogs. The pipeline does not ingest or store:
- User credentials, tokens, or private keys.
- Financial records or credit card information.
- Customer account data or internal network topologies.

### 4.2 Handling of `sourceIdentifier`
In NVD CVE 2.0 records, the `sourceIdentifier` attribute records the submitting organization or individual researcher. In several historical cases, this contains personal email addresses (e.g., `researcher@domain.com`).

**Governance Policy:**
1. **Identification:** Inspect `sourceIdentifier` values against the regular expression `^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$`.
2. **Transformation:**
   - Drop the raw `sourceIdentifier` string from `silver_cve` and all Gold tables.
   - Retain a non-identifying boolean attribute: `has_source_identifier = CASE WHEN sourceIdentifier IS NOT NULL THEN true ELSE false END`.
3. **Secrets Isolation:**
   - Any API keys (e.g., `NVD_API_KEY`) must be supplied via Databricks Secrets or environment variables.
   - No `.env` files or hardcoded API keys are permitted in repository commits.
