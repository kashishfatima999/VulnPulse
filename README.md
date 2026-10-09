# VulnPulse: Cyber Vulnerability Intelligence Lakehouse

An automated Apache Spark data engineering pipeline based on the Medallion Architecture (Lakehouse), ingesting and normalizing vulnerability intelligence from the National Vulnerability Database (NVD) and CISA Known Exploited Vulnerabilities (KEV) catalog.

[![CI](https://github.com/kashishfatima999/VulnPulse/actions/workflows/ci.yml/badge.svg)](https://github.com/kashishfatima999/VulnPulse/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Databricks%20Free%20Edition-red)](https://databricks.com/)
[![Engine](https://img.shields.io/badge/Engine-Apache%20Spark%203.x-orange)](https://spark.apache.org/)
[![BI](https://img.shields.io/badge/BI-Power%20BI-yellow)](https://powerbi.microsoft.com/)
[![Phase](https://img.shields.io/badge/Phase-Phase%202%20In%20Progress-orange)](docs/24L-2605%2624L-2512-VulnPulse_Phase1_Proposal.pdf)

---

**Authors:** Kashish Fatima & Zahra Saeed  
**Project Proposal Document:** [docs/24L-2605&24L-2512-VulnPulse_Phase1_Proposal.pdf](docs/24L-2605%2624L-2512-VulnPulse_Phase1_Proposal.pdf)  
**Technical Documentation:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | [docs/FINOPS.md](docs/FINOPS.md)  
**Repository:** [https://github.com/kashishfatima999/VulnPulse](https://github.com/kashishfatima999/VulnPulse)  

---

## Executive Summary

VulnPulse is an end-to-end data platform designed to process cybersecurity vulnerability intelligence using distributed computing. Modern analytical systems require reliable baseline history, automated incremental ingestion, schema normalization, and enrichment with active exploitation signals.

The system ingests vulnerability baselines and updates from the National Institute of Standards and Technology (NIST) National Vulnerability Database (NVD) and cross-references them against the Cybersecurity and Infrastructure Security Agency (CISA) Known Exploited Vulnerabilities (KEV) catalog. The pipeline transforms raw nested JSON payloads across Bronze, Silver, and Gold layers to power business intelligence dashboards in Power BI.

---

## Phase 1 Rubric Compliance Matrix

This repository and the formal proposal satisfy all six Phase 1 requirements:

| Requirement | Implementation Summary | Primary Reference |
|---|---|---|
| **1. Domain and Source Identification** | Cybersecurity vulnerability intelligence. Primary source: NIST NVD 2.0 JSON feeds and REST API. Enrichment: CISA KEV JSON catalog. Full load via yearly archives (2020-2026); incremental load via watermark-filtered REST API queries. | [Proposal PDF (Sections 1-4)](docs/24L-2605%2624L-2512-VulnPulse_Phase1_Proposal.pdf) |
| **2. Data Samples and Volume** | Authentic API sample extracts for both load patterns stored in `data/`. Baseline historical volume estimated at ~132 MiB compressed; incremental updates estimated at sub-MB to low single-digit MB daily. | [`data/`](data/) and [Proposal PDF (Section 5)](docs/24L-2605%2624L-2512-VulnPulse_Phase1_Proposal.pdf) |
| **3. Security and Compliance** | Identified email addresses occasionally present in NVD `sourceIdentifier`. Masking/dropping strategy defined for Silver/Gold layers with boolean retention. API credentials isolated in environment variables. | [Proposal PDF (Section 6)](docs/24L-2605%2624L-2512-VulnPulse_Phase1_Proposal.pdf) and [FINOPS.md](docs/FINOPS.md) |
| **4. Medallion Data Modeling** | Bronze raw ingestion with audit lineage; Silver normalized tables (`silver_cve`, `silver_affected_product`, `silver_cwe`, `silver_kev`); Gold analytical star/aggregate models. | [Proposal PDF (Section 7)](docs/24L-2605%2624L-2512-VulnPulse_Phase1_Proposal.pdf) and [ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| **5. Business Intelligence and Dashboards** | Designed for Power BI. Addresses five analytical questions regarding severity evolution, vendor risk, exploit response timing, and remediation watchlists with five planned visual charts. | [Proposal PDF (Section 8)](docs/24L-2605%2624L-2512-VulnPulse_Phase1_Proposal.pdf) |
| **6. Engineering Setup and FinOps** | Public GitHub repository, Databricks Free Edition guardrails, storage cap below 2.0 GB, watermark-driven compute savings, automated CI validation gate, and MIT license. | [Proposal PDF (Sections 9-10)](docs/24L-2605%2624L-2512-VulnPulse_Phase1_Proposal.pdf) and [FINOPS.md](docs/FINOPS.md) |

---

## Architecture Overview

```mermaid
flowchart TD
    subgraph Sources ["External Sources"]
        NVD_Full["NVD Yearly Feeds (2020-2026 JSON.gz)"]
        NVD_Inc["NVD CVE API 2.0 (REST Incremental)"]
        CISA_Feed["CISA KEV JSON Feed"]
    end

    subgraph Bronze ["Bronze Layer (Raw and Auditable)"]
        B_NVD["bronze_nvd_raw<br/>Raw payloads + batch ID + timestamp + hash"]
        B_CISA["bronze_cisa_raw<br/>Raw KEV catalog snapshot + timestamp"]
    end

    subgraph Silver ["Silver Layer (Cleansed and Normalized)"]
        S_CVE["silver_cve (Normalized CVE records, PII stripped)"]
        S_Prod["silver_affected_product (1:N CVE to product mapping)"]
        S_CWE["silver_cwe (1:N CVE to weakness mapping)"]
        S_KEV["silver_kev (Normalized KEV exploit metadata)"]
    end

    subgraph Gold ["Gold Layer (Curated for Analytics)"]
        G_Trend["gold_vulnerability_trends (Temporal severity aggregates)"]
        G_Vendor["gold_vendor_risk (Vendor exposure and KEV ratios)"]
        G_KEV_Resp["gold_kev_response (Days to KEV inclusion metrics)"]
        G_Watch["gold_watchlist (Actionable priority CVEs)"]
        G_Audit["pipeline_execution_logs + pipeline_watermarks (Run audit, incremental state)"]
    end

    subgraph BI ["Presentation Layer"]
        PowerBI["Power BI Intelligence Dashboard"]
    end

    NVD_Full --> B_NVD
    NVD_Inc --> B_NVD
    CISA_Feed --> B_CISA

    B_NVD --> S_CVE
    B_NVD --> S_Prod
    B_NVD --> S_CWE
    B_CISA --> S_KEV

    S_CVE --> G_Trend
    S_CVE & S_Prod --> G_Vendor
    S_CVE & S_KEV --> G_KEV_Resp
    S_CVE & S_KEV --> G_Watch
    B_NVD & B_CISA --> G_Audit

    G_Trend --> PowerBI
    G_Vendor --> PowerBI
    G_KEV_Resp --> PowerBI
    G_Watch --> PowerBI
```

---

## Data Sources and Ingestion Patterns

### 1. Full Load Baseline
- **Source:** NIST NVD 2.0 Yearly JSON Feeds (`nvdcve-2.0-{YEAR}.json.gz`).
- **Baseline Window:** 2020 through 2026.
- **Estimated Compressed Size:** Approximately 131.5 MiB across the multi-year baseline.
- **Role:** Establishes the initial historical dataset during platform setup.

### 2. Incremental Load
- **Source:** NIST NVD CVE API 2.0 (`https://services.nvd.nist.gov/rest/json/cves/2.0`).
- **Mechanism:** Filtered queries using `lastModStartDate` and `lastModEndDate` UTC timestamps.
- **Frequency:** Daily batches capturing newly published or modified CVE records.
- **Watermarking:** After each successful INCREMENTAL run the maximum source `lastModified` is appended to `pipeline_watermarks`. The next run queries from that value minus a 10-minute overlap to the current time; the duplicates the overlap creates are harmless in append-only Bronze and removed by Silver's `MERGE INTO`. BACKFILL runs use an explicit window and never move the watermark.

### 3. Enrichment Source
- **Source:** CISA Known Exploited Vulnerabilities (KEV) Catalog JSON feed.
- **Volume:** Approximately 1,700 records (~1.7 MB uncompressed).
- **Role:** Joined on `cve_id` to provide active exploitation status, ransomware association, and federal action deadlines.

---

## Security, PII Governance and FinOps

### PII Handling Strategy
Public vulnerability databases do not intentionally contain user personal data. However, the NVD `sourceIdentifier` field can contain email addresses representing submitter attribution. 
- In the Silver layer, incoming `sourceIdentifier` values matching email patterns are sanitized and dropped from analytical tables.
- A boolean flag (`has_source_identifier`) is retained for lineage accounting without exposing contact details.
- API keys are managed through environment variables or Databricks Secrets; no credentials exist in source control.

### FinOps and Resource Guardrails
The pipeline is designed to operate safely within Databricks Free Edition quotas:
- **No Big Data in Git:** Full yearly archives are excluded via `.gitignore`; only verifiable raw samples (<100 KB) are versioned in Git.
- **Watermark-Driven Compute:** Incremental batches avoid reprocessing the 130+ MiB baseline, reducing cluster runtime and memory overhead.
- **Persistent Storage Limit:** Staging files are purged once ingested into Unity Catalog Delta tables, keeping overall project storage below a 2.0 GB ceiling.

---

## Repository Structure

Only files under `notebooks/` are ever executed. Everything else is imported by them, tested by CI,
or read by people.

```text
VulnPulse/
├── .github/workflows/
│   └── ci.yml                        # CI on every PR: ruff lint, pytest (local PySpark), sample integrity
├── notebooks/                        # Thin Databricks notebooks (source format). RUN THESE.
│   ├── 00_setup_catalog.py           # Once: creates vulnpulse_bronze/silver/gold schemas + landing volume
│   ├── 01_bronze_nvd.py              # Raw-to-Bronze NVD: FULL / INCREMENTAL / BACKFILL from a landing folder
│   ├── 02_bronze_kev.py              # Raw-to-Bronze CISA KEV: full snapshot from a landing folder
│   ├── 03_silver.py                  # Bronze-to-Silver NVD + KEV: transform, quarantine, dedup, MERGE, audit
│   └── 99_failure_drills.py          # Demo only: Silver failure drills D1-D4 on scratch copies of the tables
├── src/vulnpulse/                    # Production code, imported by notebooks and tests. Never run directly.
│   ├── schemas/
│   │   ├── nvd.py                    # Explicit StructTypes for NVD pages (raw envelope) and typed CVE records
│   │   └── kev.py                    # Explicit StructTypes for the CISA KEV catalog and records
│   ├── ingestion/
│   │   ├── nvd_api.py                # NVD API 2.0 client: windows, pagination, retry, rate-limit pauses
│   │   └── landing.py                # manifest.json read/write, CLI window resolution
│   ├── bronze/
│   │   ├── nvd.py                    # Read NVD files, one row per CVE, attach metadata, append to Delta
│   │   └── kev.py                    # Download KEV catalog, one row per entry, append to Delta
│   ├── silver/
│   │   ├── ddl.py                    # Silver StructTypes + idempotent CREATE TABLE (silver_cve, silver_kev, quarantine)
│   │   ├── transform.py              # NVD raw_json -> typed silver_cve rows: UTC timestamps, CVSS v3.1/v3.0, PII rule
│   │   ├── kev.py                    # KEV raw_json -> typed silver_kev rows: DATE casts
│   │   ├── quality.py                # Quarantine rules and the valid / quarantine split, with reasons
│   │   ├── merge.py                  # Dedup on the key (latest wins), MERGE INTO, insert-only quarantine MERGE
│   │   └── params.py                 # Silver run parameters: catalog, batch_id / date-window backfill filters
│   ├── audit/
│   │   └── execution_log.py          # pipeline_execution_logs table: one row per run per layer
│   └── utils/
│       ├── params.py                 # Validated run parameters (load_type, dates, batch_id, catalog)
│       └── watermark.py              # pipeline_watermarks table and incremental window logic
├── tests/                            # pytest suite; run locally and in CI, never in Databricks
│   ├── conftest.py                   # Local SparkSession fixture, sample data path
│   ├── test_bronze_nvd.py            # Raw preservation, Bronze schema, hash stability, typed parse
│   ├── test_schemas_kev.py           # KEV envelope + typed record schema
│   ├── test_params_and_log.py        # Parameter validation, execution-log row construction
│   ├── test_nvd_api.py               # Pagination, 120-day chunking, retry/backoff (no network)
│   ├── test_watermark.py             # Incremental window rules
│   ├── test_bronze_kev.py            # KEV explode + Bronze schema
│   ├── test_landing.py               # Manifest round-trip, CLI window rules
│   ├── test_sample_payloads.py       # Phase 1 sample shape checks
│   ├── test_silver_nvd.py            # Silver NVD: casts, UTC, PII rule, CVSS pick, drift, quarantine, dedup
│   └── test_silver_kev.py            # Silver KEV casts + dedup; Silver run parameters and backfill filters
├── scripts/                          # Laptop-side tooling (Free Edition serverless has no internet)
│   ├── fetch_nvd.py                  # Fetch an NVD window (incremental or backfill) into landing/
│   ├── fetch_kev.py                  # Download the KEV catalog into landing/
│   ├── collect_phase1_samples.py     # Phase 1: re-fetches the ten-record samples
│   └── validate_samples.py           # Phase 1: verifies samples against source_manifest.json (CI)
├── data/                             # Ten-record real samples (<100 KB). No full datasets, ever.
│   ├── nvd_full_load_sample.json
│   ├── nvd_incremental_load_sample.json
│   ├── cisa_kev_sample.json
│   ├── source_manifest.json          # Capture URLs, timestamps, record counts, SHA-256 digests
│   └── README.md
├── docs/
│   ├── 24L-2605&24L-2512-VulnPulse_Phase1_Proposal.pdf   # Approved Phase 1 proposal
│   ├── ARCHITECTURE.md               # Lakehouse design and table specifications
│   ├── FINOPS.md                     # Free Edition quota, storage and testing guardrails
│   ├── EVIDENCE.md                   # Run evidence: audit rows, screenshots, failure drills
│   ├── requirements/                 # Teacher's requirement texts (phase1.txt, phase2.txt)
│   └── planning/                     # Work division and Databricks runbook
├── PROJECT_CONTRACT.md               # The rubric as hard rules. Paste into every AI prompt.
├── pyproject.toml                    # Project metadata, ruff and pytest configuration
├── requirements-dev.txt              # Dev/CI dependencies: pyspark, pytest, ruff
├── .gitattributes                    # LF line endings so SHA-256 digests match across OSes
├── landing/                          # Git-ignored. Local output of fetch_*.py before upload to the volume
├── .gitignore                        # Excludes landing/, data dumps, Delta/Parquet, venvs, caches, secrets
├── LICENSE                           # MIT
└── README.md
```

### How the pieces connect

```text
GitHub (source of truth)
   │  pull
   ▼
Laptop: scripts/fetch_*.py ──upload──► /Volumes/.../landing/<src>/<batch_id>
                                              │
Databricks Git folder ──► notebooks/01_bronze_nvd.py ──imports──► src/vulnpulse/*
                                     │
                                     ├──► workspace.vulnpulse_bronze.bronze_nvd_raw   (Delta, append-only)
                                     └──► workspace.vulnpulse_gold.pipeline_execution_logs
```

---

## Sample Data and Verification

The `data/` directory contains authentic, non-fabricated sample files captured from live endpoints:
- `nvd_full_load_sample.json`: Representative payload for historical baseline ingestion.
- `nvd_incremental_load_sample.json`: Representative payload for watermark-based incremental queries.
- `cisa_kev_sample.json`: Representative payload for enrichment joins.
- `source_manifest.json`: Full provenance tracking, including capture timestamp, source URLs, record counts, and SHA-256 digests.

### Reproducing Sample Collection
To regenerate or verify the sample payloads directly from NIST and CISA endpoints:
```bash
python scripts/collect_phase1_samples.py
```

---

## Phase 2: Pipeline Implementation

The teacher's Phase 2 requirements are in [`docs/requirements/phase2.txt`](docs/requirements/phase2.txt).
[`PROJECT_CONTRACT.md`](PROJECT_CONTRACT.md) restates them as rules every file must follow.
Status: Raw-to-Bronze and Bronze-to-Silver are implemented for both sources (NVD and CISA KEV).

### Phase 2 Rubric Compliance Matrix

| Requirement | How VulnPulse meets it | Evidence |
|---|---|---|
| Workspace and continuous version control | Databricks Free Edition (serverless, Unity Catalog). All code lives in this repository; work happens on feature branches merged to `main` through pull requests that CI must pass. Databricks Git folders pull the branches; nothing is edited outside Git. | `.github/workflows/ci.yml`, PR history |
| Data dictionary for Bronze and Silver | Bronze below and in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Column names, types and keys are declared once in code as `StructType`s, so tables and documentation cannot drift apart. Silver dictionary below. | `src/vulnpulse/bronze/nvd.py`, `kev.py`, `src/vulnpulse/silver/ddl.py` |
| Strict schema-on-read, no `inferSchema` | Every `spark.read` passes an explicit `StructType`. A typed envelope schema captures each record verbatim; the typed record schema is applied in Silver with `from_json`. | `src/vulnpulse/schemas/`, `tests/test_bronze_nvd.py` |
| Casting into Silver | Bronze keeps source strings untouched. Silver casts NVD dates to `TimestampType` (UTC), CVSS scores to `DoubleType` (a score sent as the string `"9.8"` still casts) and KEV dates to `DateType`. Every cast is a `try_` cast: a bad value becomes NULL and the row is quarantined instead of failing the batch. | `src/vulnpulse/silver/transform.py`, `kev.py`, `tests/test_silver_nvd.py` |
| `load_timestamp` on every record | Every Bronze, Silver and operational row carries `load_timestamp` (UTC). Silver rows also carry the Bronze `batch_id` they came from. | `BRONZE_NVD_SCHEMA`, `BRONZE_KEV_SCHEMA`, `EXECUTION_LOG_SCHEMA` |
| Idempotent execution with `MERGE INTO` | Bronze is append-only with a per-record `payload_sha256`. Silver deduplicates on `cve_id` (latest `last_modified_at` wins, deterministic tie-breakers), then `MERGE INTO ... ON cve_id`, updating a matched row only when the source is strictly newer. Quarantine is written with an insert-only MERGE. Verified in Databricks: `silver_cve` first run inserted 1,580 / updated 0, second run on the same Bronze inserted 0 / updated 0; `silver_kev` 1,734 then 0 / 0. | `src/vulnpulse/silver/merge.py`, `docs/EVIDENCE.md` (S2, S3, K1, K2) |
| Parameterised backfills | One notebook, three modes chosen by widgets or job parameters: FULL (any file or folder), INCREMENTAL (landing folder from the watermark), BACKFILL (landing folder for any explicit window; `fetch_nvd.py --start --end`). No hardcoded dates, paths or table names; the manifest carries the window. | `notebooks/01_bronze_nvd.py`, `scripts/fetch_nvd.py`, `src/vulnpulse/utils/params.py` |
| Schema drift handling | Raw preservation means a new source field is never lost. Known-key sets flag unmodelled fields; the samples already exposed two real cases (`affected` in NVD, `forensicTriage` in KEV). Silver compares each record's top-level keys with the known-key set and records new ones in the run's audit `parameters` (`schema_drift_keys`) without failing; a changed type is absorbed by `try_` casts; a record that still cannot be conformed (missing or malformed id, unparseable date) goes to `silver_quarantine` with a `reason` and the batch continues. Drills D1 to D4 (`notebooks/99_failure_drills.py`, on scratch copies of the tables) verified this in Databricks. | `src/vulnpulse/silver/quality.py`, `NVD_CVE_KNOWN_KEYS`, `KEV_KNOWN_KEYS`, `tests/test_silver_*.py` |
| Dedicated logging tables and audit metrics | `pipeline_execution_logs` records layer, source and parameters, start and end time, status, rows read / inserted / updated / quarantined and the error message. It is written in a `finally` block so failures are logged too. `pipeline_watermarks` keeps incremental state with history. | `src/vulnpulse/audit/execution_log.py`, `src/vulnpulse/utils/watermark.py` |
| Execution guide | Below. | this README |

### Bronze Data Dictionary

Full detail with descriptions in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Both Bronze tables are
Delta, append-only, one row per source record per batch, primary key (`cve_id`, `batch_id`).

| Table | Columns |
|---|---|
| `workspace.vulnpulse_bronze.bronze_nvd_raw` | `cve_id` STRING, `source_last_modified` STRING, `raw_json` STRING, `payload_sha256` STRING, `source_uri` STRING, `load_type` STRING, `batch_id` STRING, `load_timestamp` TIMESTAMP |
| `workspace.vulnpulse_bronze.bronze_cisa_raw` | `cve_id` STRING, `catalog_version` STRING, `date_released` STRING, `raw_json` STRING, `payload_sha256` STRING, `source_uri` STRING, `load_type` STRING, `batch_id` STRING, `load_timestamp` TIMESTAMP |
| `workspace.vulnpulse_gold.pipeline_execution_logs` | `batch_id`, `layer`, `source`, `load_type`, `parameters`, `started_at`, `finished_at`, `status`, `rows_read`, `rows_inserted`, `rows_updated`, `rows_quarantined`, `error_message`, `load_timestamp` |
| `workspace.vulnpulse_gold.pipeline_watermarks` | `source`, `watermark_ts`, `batch_id`, `load_timestamp` |

### Silver Data Dictionary

Delta tables in `workspace.vulnpulse_silver`, created idempotently from the `StructType`s in
[`src/vulnpulse/silver/ddl.py`](src/vulnpulse/silver/ddl.py). Full descriptions in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) section 2.

| Table | Primary key | Columns |
|---|---|---|
| `silver_cve` | `cve_id` | `cve_id` STRING NOT NULL, `published_at` TIMESTAMP, `last_modified_at` TIMESTAMP, `vuln_status` STRING, `description_en` STRING, `cvss_v3_score` DOUBLE, `cvss_v3_severity` STRING, `cvss_vector` STRING, `has_source_identifier` BOOLEAN, `payload_sha256` STRING, `batch_id` STRING NOT NULL, `load_timestamp` TIMESTAMP NOT NULL |
| `silver_kev` | `cve_id` | `cve_id` STRING NOT NULL, `vendor_project` STRING, `product` STRING, `vulnerability_name` STRING, `date_added` DATE, `due_date` DATE, `known_ransomware_campaign_use` STRING, `required_action` STRING, `catalog_version` STRING, `payload_sha256` STRING, `batch_id` STRING NOT NULL, `load_timestamp` TIMESTAMP NOT NULL |
| `silver_quarantine` | (`source_table`, `batch_id`, `payload_sha256`, `reason`) | `source_table` STRING NOT NULL, `cve_id` STRING, `reason` STRING NOT NULL, `raw_json` STRING, `payload_sha256` STRING NOT NULL, `batch_id` STRING NOT NULL, `load_timestamp` TIMESTAMP NOT NULL |

Quarantine reasons: `missing_cve_id`, `invalid_cve_id_format`, `unparseable_published`,
`unparseable_last_modified` (NVD), `unparseable_date_added` (KEV). `sourceIdentifier` is never stored
(PII rule); only `has_source_identifier`.

### Execution Guide

**Why acquisition runs outside Databricks.** Databricks Free Edition serverless compute has no
outbound internet: only PyPI resolves, `services.nvd.nist.gov` and `www.cisa.gov` do not (verified
8 Oct 2026, see `docs/EVIDENCE.md`). So the pipeline is split into two steps:

```text
LAPTOP (internet)                        DATABRICKS (Spark, Delta, no internet)
scripts/fetch_nvd.py  ─┐                 notebooks/01_bronze_nvd.py  ──► bronze_nvd_raw
scripts/fetch_kev.py  ─┤  upload folder  notebooks/02_bronze_kev.py  ──► bronze_cisa_raw
   page_*.json         ├───────────────► /Volumes/workspace/vulnpulse_bronze/landing/<src>/<batch_id>
   manifest.json      ─┘                 (manifest carries window, load type, source URL, batch id)
```

The notebooks never call the network. Every run is parameterised by the landing folder and its
manifest, so any historical window can be re-fetched and re-loaded at will.

**Step 1, on a laptop** (needs `pip install -r requirements-dev.txt`; `NVD_API_KEY` in the environment is optional):

| Goal | Command | Produces |
|---|---|---|
| Standard daily incremental (last 24 h) | `python scripts/fetch_nvd.py` | `landing/nvd/<batch_id>/` with `load_type=INCREMENTAL` |
| Incremental from the last watermark | `python scripts/fetch_nvd.py --start <watermark minus 10 min>` (the notebook prints this exact command after each run) | same |
| Backfill a historical window | `python scripts/fetch_nvd.py --start 2026-10-01T00:00:00 --end 2026-10-02T00:00:00` | `load_type=BACKFILL`; windows over 120 days are chunked automatically |
| KEV snapshot | `python scripts/fetch_kev.py` | `landing/kev/<batch_id>/` |

**Step 2, upload.** Databricks, Catalog, `workspace`, `vulnpulse_bronze`, `landing`: create the folder
printed by the script (`nvd/<batch_id>` or `kev/<batch_id>`) and upload every file in it.

**Step 3, run the notebook** with these widget values:

| Goal | Notebook | `load_type` | `source_path` | Watermark |
|---|---|---|---|---|
| Historical baseline from a yearly feed | `01_bronze_nvd` | `FULL` | `/Volumes/workspace/vulnpulse_bronze/landing/nvdcve-2.0-2025.json.gz` (uploaded feed file or folder) | untouched |
| Smoke test | `01_bronze_nvd` | `FULL` | default (ten-record sample inside the Git folder) | untouched |
| Incremental | `01_bronze_nvd` | `INCREMENTAL` | `/Volumes/workspace/vulnpulse_bronze/landing/nvd/<batch_id>` | read, then advanced to max `lastModified` |
| Backfill | `01_bronze_nvd` | `BACKFILL` | `/Volumes/workspace/vulnpulse_bronze/landing/nvd/<batch_id>` | untouched |
| KEV snapshot | `02_bronze_kev` | n/a | `/Volumes/workspace/vulnpulse_bronze/landing/kev/<batch_id>` | n/a |

Leave `batch_id` blank: the notebook reuses the id from `manifest.json`, so landing folder, Bronze
rows and audit row share one identifier. `start_date` / `end_date` are only needed for a BACKFILL
folder that has no manifest. After a successful run the landing folder is deleted from the volume.

**Step 4, Bronze to Silver.** Notebook `03_silver`, one run cell per source (NVD, then KEV). Each
run reads Bronze, transforms, quarantines, deduplicates, `MERGE`s and writes one
`Bronze-to-Silver` row to `pipeline_execution_logs`.

| Goal | `batch_id` | `from_date` | `to_date` | Audit `load_type` |
|---|---|---|---|---|
| Standard run (after any Bronze load) | blank | blank | blank | `FULL` |
| Backfill one Bronze batch | the Bronze `batch_id` | blank | blank | `BACKFILL` |
| Backfill a historical window | blank | `2026-10-01` | `2026-10-02` | `BACKFILL` |

Dates filter on the Bronze `load_timestamp` (UTC, inclusive). Because Silver is written with
`MERGE`, the standard run can always process all of Bronze: rows already in Silver are skipped,
newer versions update, new CVEs insert. Running it twice changes nothing. As a Job parameter, pass
the same names (`batch_id`, `from_date`, `to_date`, `catalog`).

```sql
SELECT batch_id, source, load_type, status, rows_read, rows_inserted, rows_updated, rows_quarantined
FROM workspace.vulnpulse_gold.pipeline_execution_logs WHERE layer = 'Bronze-to-Silver'
ORDER BY started_at DESC;
SELECT reason, count(*) FROM workspace.vulnpulse_silver.silver_quarantine GROUP BY 1;
```

Inspect any run:

```sql
SELECT * FROM workspace.vulnpulse_gold.pipeline_execution_logs ORDER BY started_at DESC;
SELECT * FROM workspace.vulnpulse_gold.pipeline_watermarks ORDER BY load_timestamp DESC;
SELECT batch_id, load_type, count(*) FROM workspace.vulnpulse_bronze.bronze_nvd_raw GROUP BY 1, 2;
```

### Engineering Practices

- **Thin notebooks, real modules.** Notebooks read parameters, call functions in `src/vulnpulse/` and display results. Logic is importable and unit-testable.
- **Tests before Databricks.** 58 pytest tests run on a local SparkSession against the ten-record samples, including a byte-for-byte raw-preservation check and network-free API pagination tests with injected fakes.
- **CI gates every pull request.** Ruff lint and format, pytest with local PySpark, and sample-manifest integrity. Branches never merge red.
- **Explicit, idempotent DDL.** Tables are created with `CREATE TABLE IF NOT EXISTS` from the same `StructType` the code writes with.
- **UTC everywhere.** One clock (`utc_now()`), session time zone pinned to UTC, timestamps stored as instants.
- **Failure is logged, not hidden.** Audit rows are written in `finally`; errors are re-raised after logging.
- **FinOps.** Landing files are purged after a successful append; incremental runs fetch only the changed window; the ten-record samples, not full feeds, are used for development. Acquisition runs on a laptop, so no Databricks compute is spent waiting on slow public APIs.
- **Secrets.** API keys come from Databricks secrets or job parameters, never from code.

---

## Proof

Grading is on what the pipeline does, so the evidence is kept in three forms:

| Form | Where | What it shows |
|---|---|---|
| **Screen recording, about 5 minutes** | https://youtu.be/Q1Pq-MEYE0o (unlisted) | Explicit `StructType` schemas in `src/vulnpulse/schemas/`; a live BACKFILL run of `01_bronze_nvd` from a landing folder, watermark untouched; `03_silver` re-run on unchanged Bronze with inserted 0 / updated 0 and row count equal to distinct CVEs; schema drift (`vendorComments` detected in the 2020 feed, quarantine rows and a string CVSS score cast in `99_failure_drills`); the `pipeline_execution_logs` table with successes and failures |
| **Notebook exports with outputs** | [`docs/evidence/01_bronze_nvd.html`](docs/evidence/01_bronze_nvd.html), [`docs/evidence/03_silver.html`](docs/evidence/03_silver.html) | Full notebook code and cell outputs from real Databricks runs (incremental load with watermark advance; Silver MERGE run) |
| **Audit exports and screenshots** | [`docs/EVIDENCE.md`](docs/EVIDENCE.md) and [`docs/evidence/`](docs/evidence/) | Milestone table with batch ids and row counts, CSV exports of `pipeline_execution_logs`, screenshots per milestone, failure drills, observed schema drift, and the incidents met on the way (no outbound internet on Free Edition serverless; Unity Catalog table ownership between teammates) |

Everything in the table can also be reproduced by following the Execution Guide above.

---

## Project Execution Plan

- **Phase 1 (Completed):** Proposal document, domain and source identification, sample payloads, Medallion architecture model, FinOps plan, and repository initialization.
- **Phase 2 (Done, due 10 Oct 2026):** Raw-to-Bronze for NVD (full, incremental, backfill) and CISA KEV with explicit schemas, audit logging and watermarks. Bronze-to-Silver with casting, dedup + `MERGE INTO`, quarantine, schema-drift logging and audit for both sources.
- **Phase 3:** Gold aggregate tables, Power BI business intelligence dashboard, and final documentation.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
