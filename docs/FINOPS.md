# VulnPulse FinOps, Resource Governance and Security Specification

This document defines resource optimization constraints, operational cost management, and security governance rules for the VulnPulse data engineering pipeline running on Apache Spark (Databricks Free Edition).

---

## 1. FinOps Principles and Free Tier Constraints

The project operates under Databricks Free Edition / Azure for Students limits. The platform provides serverless compute with strict core hour quotas and limited persistent storage.

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
1. Read the maximum `watermark_timestamp` from `gold_pipeline_audit`. If empty, default to baseline end date.
2. Set `lastModStartDate = watermark_timestamp - INTERVAL 10 MINUTES` (safety buffer for clock drift and in-flight commits).
3. Set `lastModEndDate = CURRENT_TIMESTAMP_UTC`.
4. Fetch paginated records from `https://services.nvd.nist.gov/rest/json/cves/2.0`.
5. Append newly fetched records into Bronze.
6. In Silver, merge incoming records into `silver_cve` using `MERGE INTO` on `cve_id` when `source.last_modified_at > target.last_modified_at`.
7. Update `gold_pipeline_audit` with the new maximum `last_modified_at` encountered.

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
