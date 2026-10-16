# Phase 2 Work Division

> **Deadline: Phase 2 is due 10 October 2026.** Phase 3 (Gold + dashboard) is due 24 October 2026.
> Source: `docs/requirements/phase2.txt`.

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
| 1 Bronze | Bronze writer: append raw payload rows with `batch_id`, `load_type`, `source_uri`, `load_timestamp` (UTC), `payload_sha256`, `raw_json` | Kashish | readers | `bronze_nvd_raw`, `bronze_cisa_raw` Delta tables | `src/vulnpulse/bronze/writer.py` |
| 1 Bronze | Parameterisation: `load_type` (FULL / INCREMENTAL / BACKFILL), `start_date`, `end_date`, `year`, `batch_id` via notebook widgets / job parameters | Kashish | writer | Same notebook runs any mode without code edits | `notebooks/01_bronze_nvd.py`, `src/vulnpulse/utils/params.py` |
| 1 Bronze | Watermark: read last successful `max(lastModified)`, apply 10-minute overlap, write new watermark only on success | Kashish | writer | `watermark` table or rows in `pipeline_execution_logs` | `src/vulnpulse/utils/watermark.py` |
| 1 Bronze | File-level audit: one row per run with source, load_type, start/end time, status, records_read, records_written, error | Kashish | writer | `pipeline_execution_logs` rows for every Bronze run | `src/vulnpulse/audit/run_audit.py` |
| 1 Bronze | Bronze tests: schema matches samples, metadata columns never null, sha256 stable, watermark advances, re-run of same batch is detectable | Kashish | all above | pytest green locally and in CI | `tests/test_bronze_*.py` |
| 2 Silver | Silver table DDL with explicit types and keys: `silver_cve`, `silver_affected_product`, `silver_cwe`, `silver_reference`, `silver_kev` | Zahra | none (uses ARCHITECTURE.md) | Empty Delta tables created idempotently | `src/vulnpulse/silver/ddl.py`, `notebooks/00_setup_catalog.py` (Silver section) |
| 2 Silver | Flatten `raw_json` -> typed columns using the Bronze schema; English description, CVSS v3.1/v3.0 fallback, severity, CPE vendor/product parsing | Zahra | Bronze schema module (can mock Bronze from `data/` samples) | Pure transformation functions, DataFrame in -> DataFrame out | `src/vulnpulse/silver/transform.py` |
| 2 Silver | PII rule: drop `sourceIdentifier`, keep `has_source_identifier` boolean | Zahra | transform | Covered by a unit test | `src/vulnpulse/silver/transform.py` |
| 2 Silver | Deduplicate per `cve_id` keeping latest `last_modified_at`, then `MERGE INTO` each Silver table | Zahra | transform | Same Bronze batch processed twice yields identical Silver | `src/vulnpulse/silver/merge.py` |
| 2 Silver | Schema drift: compatible casts (e.g. `"9.8"` -> double), unknown extra fields ignored and logged, missing required fields -> quarantine | Zahra | merge | `silver_quarantine` table with reason column; batch never aborts on a bad row | `src/vulnpulse/silver/quality.py` |
| 2 Silver | Row-level audit: inserted, updated, rejected, quarantined counts per batch | Zahra | merge | Rows appended to `pipeline_execution_logs` | `src/vulnpulse/audit/merge_audit.py` |
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

---

# Phase 3 Work Division (16 to 24 October 2026)

Full design, decisions and schedule: [`PHASE3_PLAN.md`](PHASE3_PLAN.md). Ownership follows the Phase 2
pattern: Kashish owns the Gold core, automation and the engineering half of the report; Zahra owns the
Silver extensions, the product and CWE arms of the star, the BI dashboard and the modelling half of
the report. Both review each other's PRs.

| Phase | Task | Owner | Dependency | Deliverable | Notebook / File |
|---|---|---|---|---|---|
| 3.0 Plan | Phase 3 plan, decision log, this division | Kashish | none | Merged to `main` 16 Oct | `docs/planning/PHASE3_PLAN.md` |
| 3.1 Silver+ | `silver_affected_product`: parse CPE 2.3 criteria to vendor, product, part, version bounds, `vulnerable`; quality rules; MERGE on (`cve_id`, `criteria`) | Zahra | none | Table populated from all Bronze, audit row, tests | `src/vulnpulse/silver/products.py`, `tests/test_silver_products.py`, `03_silver.py` (new cell) |
| 3.1 Silver+ | `silver_cwe`: one row per CVE × CWE id from `weaknesses`; MERGE on (`cve_id`, `cwe_id`) | Zahra | none | Table populated, audit row, tests | `src/vulnpulse/silver/cwe.py`, `tests/test_silver_cwe.py` |
| 3.2 Gold core | `gold` package skeleton, DDL for all Gold tables with `CLUSTER BY`, `dim_date` generator, `dim_severity` | Kashish | none | Empty Gold tables created idempotently; two static dims filled | `src/vulnpulse/gold/ddl.py`, `dims_static.py` |
| 3.2 Gold core | `dim_cve` (SCD1 MERGE) and `fact_cve` (days to KEV, exploited and ransomware flags, counts) | Kashish | `silver_cve`, `silver_kev` (exist) | Both tables filled; re-run inserts 0 / updates 0 | `src/vulnpulse/gold/cve.py`, `tests/test_gold_cve.py` |
| 3.2 Gold core | Gold watermark on Silver `load_timestamp`; `mode = incremental / full`; Silver-to-Gold audit rows per table | Kashish | above | `04_gold` runs end to end; log rows with rows read / inserted / updated | `src/vulnpulse/gold/run.py`, `notebooks/04_gold.py` |
| 3.3 Gold arms | `dim_vendor_product`, `fact_cve_product` | Zahra | 3.1, `fact_cve` keys from Kashish | Tables filled, idempotent, tests | `src/vulnpulse/gold/products.py` |
| 3.3 Gold arms | `dim_cwe`, `fact_cve_cwe` | Zahra | 3.1 | Tables filled, idempotent, tests | `src/vulnpulse/gold/cwe.py` |
| 3.3 Gold arms | `gold_watchlist_v` view | Kashish | `fact_cve`, `dim_cve` | View returns rows; criteria documented | `src/vulnpulse/gold/ddl.py` |
| 3.4 Automation | Databricks Job `vulnpulse_pipeline`: 01 and 02 parallel → 03 → 04, job parameters, one green run | Kashish | 3.2, 3.3 | Run page screenshot, job JSON exported to `docs/evidence/` | Databricks Jobs UI |
| 3.4 Automation | `OPTIMIZE` + clustering evidence (`DESCRIBE DETAIL` before/after) | Kashish | full Gold build | Numbers in EVIDENCE.md | `04_gold.py` final cell |
| 3.5 Model doc | `docs/GOLD_MODEL.md`: Mermaid ER diagram, every Gold table's columns, types, PK/FK | Zahra | 3.2, 3.3 DDL | Reviewed by Kashish | `docs/GOLD_MODEL.md` |
| 3.6 BI | Power BI connection to the SQL warehouse, Import of Gold + log tables, relationships in Model view, `dim_date` marked as date table | Zahra | Gold filled | Model view screenshot | `bi/VulnPulse.pbix` |
| 3.6 BI | Page 1 Vulnerability Intelligence: 4 KPI cards, Q1 line, Q2 bar, Q3 bar, Q4 histogram, Q5 table, slicers | Zahra | above | Page screenshot | `bi/VulnPulse.pbix` |
| 3.6 BI | Page 2 Pipeline Health: runs by status over time, rows per run per layer, quarantine reasons, 4 KPI cards | Zahra | above | Page screenshot, PDF export of both pages | `bi/VulnPulse.pbix`, `docs/evidence/bi_*.png` |
| 3.7 Report | Sections 1 (summary, architecture diagram), 4 (query profile DAG analysis), 5 (FinOps) | Kashish | Job run, query profile capture | Draft in repo by 21 Oct | `docs/report/VulnPulse_Phase3_Report.md` |
| 3.7 Report | Section 2 (data models, ER), BI section, decision log outcomes for Silver and BI decisions | Zahra | GOLD_MODEL.md, dashboard | Draft in repo by 22 Oct | same file, own sections |
| 3.7 Report | Assembly, consistency pass, PDF export | Both | all sections | `docs/report/VulnPulse_Phase3_Report.pdf` | `docs/report/` |
| 3.8 Docs | README Phase 3 section: Gold dictionary link, job run guide, BI connection guide, proof links; EVIDENCE.md Gold and BI milestones | Kashish, Zahra adds BI parts | everything | Merged | `README.md`, `docs/EVIDENCE.md` |
| 3.9 Freeze | Final job run, final `.pbix`, final PDF, both PRs merged, CI green | Both | all | Submission 24 Oct | n/a |

## File ownership for Phase 3

| Path | Owner |
|---|---|
| `src/vulnpulse/gold/ddl.py`, `dims_static.py`, `cve.py`, `run.py`, `notebooks/04_gold.py` | Kashish |
| `src/vulnpulse/gold/products.py`, `cwe.py` | Zahra |
| `src/vulnpulse/silver/products.py`, `cwe.py`, new cells in `03_silver.py` | Zahra |
| `tests/test_gold_cve.py`, `tests/test_gold_run.py` | Kashish |
| `tests/test_silver_products.py`, `test_silver_cwe.py`, `test_gold_products.py`, `test_gold_cwe.py` | Zahra |
| `docs/GOLD_MODEL.md`, `bi/` | Zahra |
| `docs/report/` sections 1, 4, 5 | Kashish |
| `docs/report/` sections 2, 3 (BI decisions), BI section | Zahra |
| `README.md`, `docs/EVIDENCE.md` | Shared, own sections only, never the same day |

Interface contract between the two halves: Kashish publishes `src/vulnpulse/gold/ddl.py` (all Gold
schemas, including the ones Zahra fills) on 16 Oct so both can code against fixed column names and keys.
Zahra does not wait for `fact_cve` to build `fact_cve_product`; both read Silver, not each other.

## Branches

```text
main
├── planning-phase3        this plan (merged first)
├── phase3-kashish         Gold core, automation, report engineering sections
└── phase3-zahra           Silver extensions, Gold arms, BI, report model sections
```
