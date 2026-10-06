# Phase 2 Work Division

Two-person split for the Phase 2 pipeline (ingestion, Bronze, Silver, audit, tests).
Phase 1 design is approved and unchanged: table names and column names below come from
[`docs/ARCHITECTURE.md`](../ARCHITECTURE.md).

| Owner | Area |
|---|---|
| **Kashish** | Source acquisition (NVD, CISA), Bronze layer, parameters and backfill, watermark, file-level audit, Databricks workspace setup |
| **Zahra** | Silver layer, MERGE / idempotency, schema drift and quarantine, row-level audit, Silver data-quality rules |
| **Both** | Tests for your own code, integration run, documentation of your own layer, final evidence |

This is not a forced 50/50. Kashish has more pieces, Zahra has the harder single piece (MERGE +
drift + quarantine). Re-balance only if one side is clearly idle.

---

## 1. Task table

| Phase | Task | Owner | Dependency | Deliverable | Notebook / File |
|---|---|---|---|---|---|
| 0 Setup | Connect GitHub repo to Databricks as a Git folder (one folder per person) | Each | none | Git folder visible in Workspace, can pull `main` | n/a |
| 0 Setup | Create Unity Catalog schemas and landing volume | Kashish | Databricks login | `workspace.vulnpulse_bronze`, `vulnpulse_silver`, `vulnpulse_gold` schemas; `landing` volume | `notebooks/00_setup_catalog.py` |
| 0 Setup | Project contract file for AI and humans | Kashish | none | List of hard rules (no inferSchema, UTC, MERGE, etc.) | `PROJECT_CONTRACT.md` |
| 0 Setup | Shared Spark/test scaffolding | done | none | pytest + local Spark fixture, ruff, CI | `tests/conftest.py`, `pyproject.toml`, `.github/workflows/ci.yml` |
| 1 Bronze | Explicit StructType for the NVD API page and for the KEV catalog | Kashish | none | Schemas as Python modules, unit-tested against `data/` samples | `src/vulnpulse/schemas/nvd.py`, `schemas/kev.py` |
| 1 Bronze | NVD full-load reader (yearly `nvdcve-2.0-YYYY.json.gz` feeds, 2020-2026) | Kashish | schemas | Function: year -> landing file -> DataFrame | `src/vulnpulse/ingestion/nvd_full.py` |
| 1 Bronze | NVD incremental reader (API 2.0, `lastModStartDate`/`lastModEndDate`, pagination, retry, optional API key from secret) | Kashish | schemas | Function: (start, end) -> DataFrame + page count | `src/vulnpulse/ingestion/nvd_incremental.py` |
| 1 Bronze | CISA KEV snapshot reader | Kashish | schemas | Function: -> DataFrame + catalogVersion | `src/vulnpulse/ingestion/kev.py` |
| 1 Bronze | Bronze writer: append raw payload rows with `batch_id`, `load_type`, `source_uri`, `ingested_at` (UTC), `payload_sha256`, `raw_json` | Kashish | readers | `bronze_nvd_raw`, `bronze_cisa_raw` Delta tables | `src/vulnpulse/bronze/writer.py` |
| 1 Bronze | Parameterisation: `load_type` (FULL / INCREMENTAL / BACKFILL), `start_date`, `end_date`, `year`, `batch_id` via notebook widgets / job parameters | Kashish | writer | Same notebook runs any mode without code edits | `notebooks/01_bronze_nvd.py`, `src/vulnpulse/utils/params.py` |
| 1 Bronze | Watermark: read last successful `max(lastModified)`, apply 10-minute overlap, write new watermark only on success | Kashish | writer | `watermark` table or rows in `gold_pipeline_audit` | `src/vulnpulse/utils/watermark.py` |
| 1 Bronze | File-level audit: one row per run with source, load_type, start/end time, status, records_read, records_written, error | Kashish | writer | `gold_pipeline_audit` rows for every Bronze run | `src/vulnpulse/audit/run_audit.py` |
| 1 Bronze | Bronze tests: schema matches samples, metadata columns never null, sha256 stable, watermark advances, re-run of same batch is detectable | Kashish | all above | pytest green locally and in CI | `tests/test_bronze_*.py` |
| 2 Silver | Silver table DDL with explicit types and keys: `silver_cve`, `silver_affected_product`, `silver_cwe`, `silver_reference`, `silver_kev` | Zahra | none (uses ARCHITECTURE.md) | Empty Delta tables created idempotently | `src/vulnpulse/silver/ddl.py`, `notebooks/00_setup_catalog.py` (Silver section) |
| 2 Silver | Flatten `raw_json` -> typed columns using the Bronze schema; English description, CVSS v3.1/v3.0 fallback, severity, CPE vendor/product parsing | Zahra | Bronze schema module (can mock Bronze from `data/` samples) | Pure transformation functions, DataFrame in -> DataFrame out | `src/vulnpulse/silver/transform.py` |
| 2 Silver | PII rule: drop `sourceIdentifier`, keep `has_source_identifier` boolean | Zahra | transform | Covered by a unit test | `src/vulnpulse/silver/transform.py` |
| 2 Silver | Deduplicate per `cve_id` keeping latest `last_modified_at`, then `MERGE INTO` each Silver table | Zahra | transform | Same Bronze batch processed twice yields identical Silver | `src/vulnpulse/silver/merge.py` |
| 2 Silver | Schema drift: compatible casts (e.g. `"9.8"` -> double), unknown extra fields ignored and logged, missing required fields -> quarantine | Zahra | merge | `silver_quarantine` table with reason column; batch never aborts on a bad row | `src/vulnpulse/silver/quality.py` |
| 2 Silver | Row-level audit: inserted, updated, rejected, quarantined counts per batch | Zahra | merge | Rows appended to `gold_pipeline_audit` | `src/vulnpulse/audit/merge_audit.py` |
| 2 Silver | Silver tests: casting, dedup, MERGE update path, quarantine path, drift does not kill batch | Zahra | all above | pytest green locally and in CI | `tests/test_silver_*.py` |
| 3 Integrate | End-to-end run on tiny data: NVD sample -> Bronze -> Silver | Both | Bronze + Silver done | Screenshots / audit rows as evidence | `notebooks/01_bronze_nvd.py`, `notebooks/03_silver.py` |
| 3 Integrate | Failure drills: duplicate batch, bad type, missing column, extra column, invalid CVSS, re-run after failure | Both | integration | Table of drill -> expected -> observed in docs | `docs/EVIDENCE.md` |
| 3 Integrate | Scale ladder: one year feed, then incremental window, then full 2020-2026 | Kashish runs, Zahra verifies Silver counts | integration | Row counts and run times recorded in audit | n/a |
| 3 Integrate | Databricks Job: Bronze task -> Silver task, daily schedule (paused until final) | Kashish | integration | Job definition, one successful scheduled run | Databricks Jobs UI, documented in `docs/RUNBOOK.md` |
| 4 Docs | Bronze data dictionary + runbook (how to run FULL, INCREMENTAL, BACKFILL) | Kashish | own layer | `docs/RUNBOOK.md`, Bronze section of `ARCHITECTURE.md` | docs |
| 4 Docs | Silver data dictionary + quality rules + quarantine reasons | Zahra | own layer | Silver section of `ARCHITECTURE.md` | docs |
| 4 Docs | README Phase 2 section, final PR, freeze | Both | everything | Merged `main`, green CI, final Databricks pull | `README.md` |

---

## 2. File ownership (avoid merge conflicts)

Only the owner edits these without asking first.

| Path | Owner |
|---|---|
| `src/vulnpulse/schemas/`, `src/vulnpulse/ingestion/`, `src/vulnpulse/bronze/`, `src/vulnpulse/utils/` | Kashish |
| `src/vulnpulse/silver/` | Zahra |
| `src/vulnpulse/audit/run_audit.py` | Kashish |
| `src/vulnpulse/audit/merge_audit.py` | Zahra |
| `notebooks/00_setup_catalog.py` | Kashish writes it, Zahra adds the Silver DDL call in one PR |
| `notebooks/01_bronze_nvd.py`, `notebooks/02_bronze_kev.py` | Kashish |
| `notebooks/03_silver.py` | Zahra |
| `tests/test_bronze_*.py` | Kashish |
| `tests/test_silver_*.py` | Zahra |
| `tests/conftest.py`, `pyproject.toml`, `requirements-dev.txt`, `.github/` | Kashish (shared, change via PR, tell the other) |
| `README.md`, `docs/ARCHITECTURE.md` | Shared. Edit only your own layer's section. Never both in the same day. |

The **interface between you two is the Bronze table schema** (six columns, see ARCHITECTURE.md
section 1). Zahra does not need Kashish's ingestion code to start: build a fake
`bronze_nvd_raw` DataFrame from `data/nvd_full_load_sample.json` in a test fixture and develop
Silver against that. Kashish does not need Silver to finish Bronze. You only truly meet at
Phase 3.

---

## 3. Branches

```
main                       protected: CI green + 1 review to merge
├── phase2-kashish         Kashish's working branch
└── phase2-zahra           Zahra's working branch
```

Open a PR from your branch to `main` whenever a task row above is done and tested. Small PRs,
roughly one task row each. Pull `main` into your branch every morning.

---

## 4. Definition of done for any task

1. Code lives in `src/`, not inside the notebook.
2. `ruff check .` and `ruff format --check .` pass.
3. At least one pytest covers it and passes locally with `pytest`.
4. It has run once in Databricks on the ten-record sample without manual edits.
5. The PR description says what to run and what the output should look like.
