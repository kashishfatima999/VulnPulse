# Phase 2 Run Evidence

Proof that the pipeline behaves as the rubric requires, collected from real runs in Databricks.
Screenshots live in `docs/evidence/` (PNG, under 500 KB each). Audit table exports live there too as
CSV, so they can be read and diffed without opening images.

Exports so far:

| File | Content |
|---|---|
| `evidence/pipeline_execution_logs_2026-10-08.csv` | Every Raw-to-Bronze run up to the end of 8 Oct 2026: 4 sample FULL loads, 1 INCREMENTAL (862 rows), 1 BACKFILL (708 rows), 1 KEV FULL (1,734 rows), 2 logged failures |
| `evidence/pipeline_execution_logs_2026-10-09.csv` | Both layers up to 9 Oct 2026 16:38 UTC: adds the Silver first runs and re-runs of 8 Oct, the 2020 yearly feed FULL load (21,077 rows), and the Silver runs after it, including three FAILURE rows from the table-ownership incident below |
| `evidence/bronze-to-silver-2026-10-09.csv` | Bronze-to-Silver rows only, 9 Oct: repeated full passes over 22,697 Bronze rows with inserted 0 / updated 0 |
| `evidence/01_bronze_nvd.html` | Databricks notebook export with outputs: the INCREMENTAL run of 9 Oct (watermark before/after, next-fetch command, batch summary, watermark table) |
| `evidence/03_silver.html` | Databricks notebook export with outputs: Bronze-to-Silver run for NVD and KEV with MERGE counts, drift keys and audit rows |
| Screen recording | https://youtu.be/Q1Pq-MEYE0o (unlisted, about 5 min): schemas, live BACKFILL, Silver re-run with 0/0, drift and quarantine, log table |
| `evidence/silver_to_gold_logs_2026-10-16.csv` | Phase 3 session 1: two `04_gold` runs, `Silver-to-Gold` rows for `dim_date` (15,706) and `dim_severity` (6), identical counts on the re-run |
| `evidence/silver_to_gold_logs_2026-10-17.csv` | Phase 3 sessions 1 and 2: four `04_gold` runs; adds `dim_cve` and `fact_cve` first build (25,777 inserted each) and the re-run (0 / 0) |
| `evidence/silver_to_gold_logs_2026-10-17b.csv` | Phase 3 session 3 added: Gold run with 42,921 CVEs in scope (17,144 inserted, 425 / 812 updated) and the no-op run that read 0 rows |
| `evidence/pipeline_execution_logs_2026-10-17.csv` | All three layers from 16 Oct: the G3 chain in time order, Bronze INCREMENTAL 18,066 → Silver 17,144 / 920 → Gold 17,144 / 425 / 812 → Gold no-op |
| `evidence/job_807530551161428_bronze_nvd.html`, `..._bronze_kev.html`, `..._silver.html`, `..._gold.html` | Databricks exports with outputs of the four tasks of the green `vulnpulse_pipeline` run (G4): the complete Bronze → Silver → Gold chain executed by the Job |
| `evidence/g5_optimize_facts.csv` | `DESCRIBE DETAIL` before/after `OPTIMIZE` on the three facts (G5) |
| `evidence/pipeline_execution_logs_2026-10-17b.csv` | All three layers through the Job runs: the green run's chain (Bronze 1,748 and 793 → Silver 277 / 490 and 14 / 4 → Gold 782 scoped, 277 / 370 and 277 / 347) followed by the four Bronze FAILURE rows of the second run whose landing folders had already been purged (G4b) |

How to capture an audit row after any run:

```sql
SELECT batch_id, layer, load_type, source, status, rows_read, rows_inserted, started_at, finished_at
FROM workspace.vulnpulse_gold.pipeline_execution_logs ORDER BY started_at DESC LIMIT 10;
```

## Bronze milestones

| # | Run | What it proves | Status | Evidence |
|---|---|---|---|---|
| B1 | `01_bronze_nvd` FULL on the ten-record sample | Explicit-schema read, metadata columns, audit row | Done 8 Oct 2026 | `evidence/b1_bronze_rows.png`, `evidence/b1_audit.png` |
| B2 | Same run again, new batch | Bronze is append-only; identical `payload_sha256` per CVE across batches | Done 8 Oct 2026 | `evidence/b2_two_batches.png` |
| B4-fail | `01_bronze_nvd` INCREMENTAL, first attempt calling the NVD API from the notebook | Failure path: `URLError` after 4 retries, FAILURE row written to `pipeline_execution_logs` with `error_message`, watermark table untouched | Done 8 Oct 2026 | `evidence/b4_failure_logged.png` |
| B4 | `01_bronze_nvd` INCREMENTAL from an uploaded landing folder (2-hour window, 862 records) | Manifest-driven window, explicit-schema read of API pages, watermark created at `2026-10-08T13:28:04Z` = max `lastModified` seen, not the window end; next-fetch command printed with 10-min overlap (`--start 2026-10-08T13:18:04`) | Done 8 Oct 2026, batch `20261008T133135Z-a693bbde` | `evidence/pipeline_execution_logs_2026-10-08.csv` |
| B4b | INCREMENTAL again, landing folder `nvd/20261009T154427Z-c1c7f31e` (2,731 records fetched with `--start 2026-10-08T13:18:04`, the previous watermark minus 10 min) | Window `2026-10-08T13:18:04 -> 2026-10-09T15:44:27`; `watermark before run: 2026-10-08 13:28:04`, `watermark after run: 2026-10-09 15:44:02`; overlap duplicates absorbed downstream by Silver MERGE (see end-to-end section: inserted 2,490 / updated 139) | Done 9 Oct 2026, read 2,731 / wrote 2,731. A first attempt ran as FULL on the sample by mistake and is kept for honesty (`evidence/b4b_attempt_full_sample_run.png`) | `evidence/01_bronze_nvd.html`, `evidence/pipeline_execution_logs_2026-10-09.csv` |
| B5b | BACKFILL run live on camera, landing folder `nvd/20261009T175558Z-c76b7d3b` (636 records, window 2026-10-02 -> 2026-10-03) | Backfill of an arbitrary past day from a manifest; watermark table unchanged | Done 9 Oct 2026 | Screen recording, https://youtu.be/Q1Pq-MEYE0o |
| B5 | `01_bronze_nvd` BACKFILL for 2026-10-01 to 2026-10-02 (708 records) | Explicit window processed from the manifest; watermark table still exactly one row (`13:28:04Z`) afterwards | Done 8 Oct 2026, batch `20261008T133347Z-a8a9241c` | `evidence/pipeline_execution_logs_2026-10-08.csv` |
| B6 | `02_bronze_kev` from an uploaded landing folder (catalog 2026.10.04, 1,734 entries) | Second source, catalog version lifted, manifest batch id reused | Done 8 Oct 2026, batch `20261008T133204Z-097ea6cd` | `evidence/pipeline_execution_logs_2026-10-08.csv` |
| B3 | `01_bronze_nvd` FULL on the real NVD 2020 yearly feed (`nvdcve-2.0-2020.json.gz`, 13.4 MB) uploaded to `landing/feeds/` | Baseline load at real volume with the same explicit envelope schema; one 20k-row batch | Done 9 Oct 2026, batch `20261009T161039Z-05533ac3`, read 21,077 / wrote 21,077 | `evidence/b3_yearly_feed_full_load.png`, `evidence/pipeline_execution_logs_2026-10-09.csv` |

## Silver milestones (Zahra)

All runs on 8 Oct 2026 in `notebooks/03_silver`, serverless, against the Bronze state above
(NVD: 40 FULL + 862 INCREMENTAL + 708 BACKFILL = 1,610 rows, 1,580 distinct CVEs; KEV: 1,734 rows).

| # | Run | What it proves | Observed | Evidence |
|---|---|---|---|---|
| S1 | Silver DDL (`ddl.ensure_tables`), run twice | Explicit types and keys, `load_timestamp` and `batch_id` on every table; DDL is re-runnable | 3 tables created; second run no-op; `DESCRIBE` shows TIMESTAMP / DOUBLE / BOOLEAN columns | `evidence/s1_silver_ddl.png` |
| S1b | Transform preview over all Bronze | Casting and flattening | 1,610 rows, 1,580 distinct CVEs, 0 null ids / published / last_modified, 159 null v3 scores (v2-only or unscored CVEs), 0 drift keys | `evidence/s1b_transform_preview.png` |
| S2 | `03_silver` NVD, first run | Dedup + `MERGE INTO` | read 1,610, inserted 1,580, updated 0, quarantined 0; `silver_cve` 1,580 rows = 1,580 distinct | `evidence/s2_first_run.png` (older audit row, bottom) |
| S3 | Same run again, same Bronze | Idempotency | read 1,610, **inserted 0, updated 0**, quarantined 0; still 1,580 rows | `evidence/s3_second_run.png` (newer audit row, top) |
| K1 | `03_silver` KEV, first run | Second source through the same path | read 1,734, inserted 1,734, updated 0, quarantined 0; dates 2021-11-03 to 2026-10-04 | `evidence/k1_kev_first_run.png` |
| K2 | KEV again | Idempotency | **inserted 0, updated 0**, quarantined 0 | `evidence/k2_kev_second_run.png` |

Note: on 8 Oct the S2 and S3 audit rows share one `batch_id`, because the run id was minted once in
the parameter cell and the run cell was executed twice. Since 9 Oct each execution of a run cell mints
its own id, so every audit row is unique.

## Gold milestones (Phase 3)

Plan and decision log: `docs/planning/PHASE3_PLAN.md`. All runs in `notebooks/04_gold`, serverless.

| # | Run | What it proves | Observed | Evidence |
|---|---|---|---|---|
| G1 | `04_gold` first run, 16 Oct 2026, run `20261016T161439Z-34bfd7e0` | Star schema DDL is explicit and idempotent: 8 tables created with `CLUSTER BY` on the three facts; 8 PK and 14 FK informational constraints accepted by Unity Catalog; `gold_watchlist_v` created; `dim_date` and `dim_severity` generated and logged | 8 `table ready`, 22 `constraint ... added`, `dim_date: 15706 rows written`, `dim_severity: 6 rows written`; 1988 has 366 days and 105 weekend days; two `Silver-to-Gold` SUCCESS rows | `evidence/g1_gold_first_run.png`, `evidence/silver_to_gold_logs_2026-10-16.csv` |
| G1b | Same notebook again, run `20261016T183725Z-4eb32057` | Re-running the DDL and static dimensions changes nothing: constraints report `exists`, same 15,706 and 6 rows, two more log rows with the same counts | Identical counts in the log export | `evidence/g1_gold_second_run_idempotent.png` |
| G2 | `04_gold` with section 3, 16 Oct 2026 19:12 UTC, run `20261016T191235Z-8b2b0e2c` | `dim_cve` (SCD1) and `fact_cve` (CVE grain: date keys, severity key, exploitation and ransomware flags, days to KEV) built from `silver_cve` left-joined to `silver_kev` and written with a change-aware MERGE | `silver_cve rows read: 25777`; `dim_cve: inserted 25777, updated 0`; `fact_cve: inserted 25777, updated 0`; `fact_rows = distinct_cves`; two `Silver-to-Gold` SUCCESS rows, 11 s and 7 s | `evidence/g2_cve_core_first_run.pdf`, `evidence/silver_to_gold_logs_2026-10-17.csv` |
| G2b | Same notebook again, run `20261016T191618Z-0feb9b60` | Gold idempotency: the MERGE updates only when a business column differs (`batch_id` and `load_timestamp` excluded), so an unchanged Silver yields no writes | `dim_cve: inserted 0, updated 0`; `fact_cve: inserted 0, updated 0`; static dims rewritten with identical counts | `evidence/g2_cve_core_second_run_idempotent.pdf` |
| G3 | End-to-end incremental, 16 Oct 2026 20:09 to 20:16 UTC. Laptop fetch of 18,066 NVD records (9 to 16 Oct) → `01_bronze_nvd` INCREMENTAL batch `20261016T194116Z-34675cb8` → `03_silver` → `04_gold` run `20261016T201254Z-093c5ab4` | One landing folder flows Bronze → Silver → Gold with no manual data step in between. Gold's first run after the watermark code shipped finds no watermark, scopes every CVE (same as `full`), merges, then writes the `gold_from_silver` watermark | Bronze: read 18,066 / wrote 18,066. Silver: read 44,130, inserted 17,144, updated 920. Gold: scope 42,921 CVEs; `dim_cve` inserted 17,144 / updated 425; `fact_cve` inserted 17,144 / updated 812 (facts change more often than descriptive attributes: `last_modified_date_key` moves on every NVD re-analysis) | `evidence/g3_gold_incremental_first_watermark.png`, `evidence/pipeline_execution_logs_2026-10-17.csv` |
| G3b | `04_gold` again, run `20261016T201529Z-e4e461bf` | With the watermark in place and no newer Silver rows, the scope is empty: Gold reads 0 rows instead of 42,921 and writes nothing. This is the incremental saving the design promised | `scope: 0 CVEs`; `dim_cve: read 0, inserted 0, updated 0`; `fact_cve: read 0, inserted 0, updated 0`; `gold watermark unchanged` | `evidence/g3_gold_incremental_noop.png`, `evidence/silver_to_gold_logs_2026-10-17b.csv` |
| G4 | Databricks Job `vulnpulse_pipeline` (job id 403966109062622), 17 Oct 2026 02:02 local. Four notebook tasks on Serverless: `bronze_nvd` and `bronze_kev` in parallel → `silver` → `gold`, parameters mapped onto the notebook widgets | Gold is linked to the end of the pipeline: one Run now takes a landing folder through all three layers with no manual step between them | Run `807530551161428` succeeded, 4 min 48 s, all four tasks green. Per task: `bronze_nvd` 2 min 26 s, read 793 / wrote 793, NVD watermark 19:40:49 → 20:18:28; `bronze_kev` 1,748 rows, catalog 2026.10.16; `silver` 56 s, NVD read 44,923 / inserted 277 / updated 490 (drift key `vendorComments` again), KEV read 3,482 / inserted 14 / updated 4, `silver_cve` now 43,198 rows = distinct CVEs; `gold` watermark before 20:11:04, scope 785 CVEs, `dim_cve` read 782 / inserted 277 / updated 370, `fact_cve` read 782 / inserted 277 / updated 347. Gold updated fewer rows than Silver (370 vs 490) because the Gold MERGE only rewrites rows whose business columns changed; 3 of the 785 scoped ids were KEV-only changes for CVEs not yet in `silver_cve` | `evidence/g4_job_dag.png`, `evidence/g4_job_runs_green_then_purged_input.png`, `evidence/job_807530551161428_*.html` (4 task exports with outputs), `evidence/g4_task_*.png`, `evidence/vulnpulse_pipeline_job.json` |
| G4b | Second Run now launched while the first was still running (queued, then executed) | Failure handling in the orchestrator: the first run had already purged both landing folders, so both Bronze tasks failed on the missing input and `silver` and `gold` were skipped as upstream-failed. No partial or empty Gold was produced | Run `334202137385542` failed after 5 min 53 s with `RunExecutionError`; `silver` and `gold` shown as skipped. In production the fetch step writes a new folder per run and the job is started with that path as a run parameter ("Run now with different parameters"), so a re-run is never pointed at consumed input | same screenshot |
| G5 | `04_gold` with `optimize = yes`: `DESCRIBE DETAIL` → `OPTIMIZE` → `DESCRIBE DETAIL` on the three facts | Read-optimisation method on liquid-clustered facts, measured rather than claimed | `fact_cve`: 1 file, 0.27 MB before and after, `numFilesAdded = 0`, 10.3 s. Serverless Delta had already kept the table in a single compact file across four MERGEs, so `OPTIMIZE` had nothing to compact. The bridge facts were still empty (0 files). Honest conclusion for the report: at this scale clustering is declared for correctness of future growth and `OPTIMIZE` is a no-op; the benefit shows only on tables with many files | `evidence/g5_optimize_facts.csv` |
| G6 (Zahra) | `03_silver` with the two Phase 3 child cells, 23 Oct 2026 | `silver_affected_product` (CPE 2.3 criteria parsed into part, vendor, product, version bounds) and `silver_cwe` (English weakness ids) built from the latest Bronze version of every CVE, MERGE on composite keys, bad values quarantined, one `Bronze-to-Silver` audit row each | `silver_affected_product`: read 314,820 exploded criteria, inserted 292,055 (26,380 CVEs, 29,490 vendor/product pairs, 211,036 vulnerable rows), quarantined 1 (`invalid_cpe_criteria`). `silver_cwe`: read 43,053, inserted 39,710 (35,235 CVEs, 483 distinct ids), quarantined 0. `silver_cve` and `silver_kev` cells in the same run: inserted 0, updated 0 | `evidence/g6_silver_child_tables.png` |
| G6b (Zahra) | `04_gold` incremental, 23 Oct 2026 16:31 UTC, run `20261023T163134Z-9f7913bd` | Product and CWE arms of the star written inside `04_gold` (section 3b), scoped to the same changed-CVE set as `dim_cve`/`fact_cve`, so the Job refreshes all eight tables; the Gold watermark now advances in its own cell (3c) only after all ten table writes succeed | `dim_vendor_product`: read 292,055, inserted 19,216. `fact_cve_product`: read 292,055, inserted 126,081 (vulnerable CPEs only, one row per CVE × vendor/product). `dim_cwe`: read 39,710, inserted 483. `fact_cve_cwe`: read 39,710, inserted 39,710. `fact_cve`: product and CWE counts filled in. Watermark advanced to 2026-10-23 13:20:27 UTC. All `Silver-to-Gold` rows SUCCESS. Top exploited weaknesses: CWE-787, CWE-22, CWE-78 | `evidence/g6_gold_arms_first_run.png`, `evidence/g6_gold_arms_results.png`, `evidence/silver_to_gold_logs_2026-10-23.csv` |
| G6c (Zahra) | `04_gold` again, 23 Oct 2026 16:41 UTC | Gold idempotency for the new tables | `dim_vendor_product`, `fact_cve_product`, `dim_cwe`, `fact_cve_cwe`, `dim_cve`, `fact_cve`: read 0, inserted 0, updated 0; `gold watermark unchanged (no newer Silver rows)`. Only the generated `dim_date` (15,706) and `dim_severity` (6) are rewritten, by design | `evidence/g6_gold_arms_second_run_idempotent.png` |
| G7 (Zahra) | Power BI Desktop → Databricks connector → Serverless Starter Warehouse, Import mode, 23 Oct 2026. File `bi/VulnPulse.pbix` | The BI layer reads Gold directly and its semantic model mirrors the star: the same 14 relationships as `FOREIGN_KEYS` in `gold/ddl.py`, one-to-many, single direction; `dim_date` marked as the date table; the three role-playing date keys of `fact_cve` (`last_modified`, `kev_added`, `kev_due`) inactive. `gold_watchlist_v`, `pipeline_execution_logs`, `pipeline_watermarks` and `silver_quarantine` loaded as standalone reporting tables | **Page 1, Vulnerability Intelligence:** KPI cards (43K CVEs, 5K critical, 223 exploited, median 545 days to KEV); CVEs per year by severity (Q1); top 10 vendors by distinct exploited CVEs, led by Microsoft, Debian, Oracle (Q2); top 10 CWEs among exploited CVEs, led by CWE-787, CWE-22, CWE-78 (Q3); histogram of days from publication to KEV in 30-day bins (Q4); watchlist table from `gold_watchlist_v` (Q5); year and severity slicers. **Page 2, Pipeline Health:** 94 logged runs, 13 failures, last run 23 Oct 16:42, Gold watermark 13:20:27 UTC, 1 quarantined row; runs per day by status; rows inserted and updated per layer; full run log table; layer slicer. Authentication: the workspace does not let non-admin users create personal access tokens, so the connector signs in with OAuth; no credential is stored in the `.pbix` or in Git (contract rule 27) | `bi/VulnPulse.pbix`, `bi/VulnPulse.pdf`, `evidence/bi_model_view.png`, `evidence/bi_page1.png`, `evidence/bi_page2.png` |

Notes on G6:

- **Permissions.** Gold objects belong to the account that created them (Kashish). The first `04_gold` run from Zahra's account failed on `CREATE OR REPLACE VIEW gold_watchlist_v` (needs `MANAGE`). After `GRANT USE SCHEMA, SELECT, MODIFY, CREATE TABLE` on `vulnpulse_gold` and `MANAGE` on the view and the two static dimensions, the run succeeded. FK constraints that reference `dim_date` / `dim_severity` are reported as `skipped` from Zahra's account (they already exist from G1); `ensure_constraints` never fails a load.
- **Counting on bridge facts.** `fact_cve_product` is one row per CVE × vendor/product, so a vendor with many products per CVE (Qualcomm chipsets) must be measured with `COUNT(DISTINCT cve_id)`, not `SUM(is_exploited)`. The `04_gold` results query and the Power BI measure use distinct CVEs.

## Environment finding: no outbound internet on Free Edition serverless

Diagnostic run from a notebook cell on 8 Oct 2026:

```text
DNS FAIL services.nvd.nist.gov gaierror(-2, 'Name or service not known')
DNS FAIL www.cisa.gov gaierror(-2, 'Name or service not known')
DNS ok  pypi.org 151.101.192.223
HTTP FAIL https://www.cisa.gov/... URLError(gaierror(-3, 'Temporary failure in name resolution'))
HTTP FAIL https://services.nvd.nist.gov/... URLError(gaierror(-3, 'Temporary failure in name resolution'))
```

Decision: acquisition moved to laptop-side scripts that write a landing folder with a manifest; the
notebooks read the folder from the volume and never call the network. The first failed INCREMENTAL run
stays in `pipeline_execution_logs` as evidence that failures are logged with their error.

## End-to-end after real-volume loads (9 Oct 2026)

After B3, `03_silver` was run over all 22,697 Bronze rows. `silver_cve` grew from 1,580 to 22,655
distinct CVEs (`evidence/e2e_silver_after_real_loads.png`); 22,697 - 22,655 = 42 Bronze rows were
older versions of CVEs already present, collapsed by dedup + MERGE. Every subsequent full pass
reports inserted 0 / updated 0. The run also surfaced live schema drift: `schema_drift_keys
['vendorComments']`, a top-level NVD field absent from the typed schema, detected and logged with no
crash and no data loss (it stays in `raw_json`).

After B4b (the 2,731-record incremental), `03_silver` read 25,428 Bronze rows and reported
**inserted 2,490, updated 139, quarantined 0** for NVD and 0 / 0 for KEV (`evidence/03_silver.html`).
That is the incremental path end to end: new CVEs inserted, CVEs modified since the last watermark
updated through the MERGE update branch, everything else untouched. The 2,731 - 2,490 - 139 = 102
remaining rows were overlap duplicates or older versions, collapsed by dedup and the
"strictly newer" MERGE condition.

**Incident, table ownership.** Zahra created the Silver tables, so Unity Catalog made her their
owner; the schema owner (Kashish) had no SELECT on `silver_quarantine`. Three `03_silver` runs
(16:14, 16:18, 16:30 UTC) are logged as FAILURE with `INSUFFICIENT_PERMISSIONS`. In those runs the
`silver_cve` MERGE had already succeeded (that is when the 21,000 inserts happened) and only the
quarantine MERGE failed, but the notebook assigned the counts after both merges, so the FAILURE rows
show inserted 0. Fixes: table privileges granted / ownership transferred (documented in
`docs/planning/DATABRICKS_FLOW.md`), and the notebook now records MERGE counts immediately after each
MERGE so a later step failing cannot hide what was written.

## Failure drills

Silver drills D1 to D4 run in `notebooks/99_failure_drills.py` against scratch copies
(`drill_silver_cve`, `drill_silver_quarantine`) so production Silver is never modified. They were
first run on 8 Oct 2026 as the last cell of `03_silver` and moved to their own notebook afterwards;
the code is unchanged.

| Drill | Expected | Observed | Evidence |
|---|---|---|---|
| Same Bronze batch processed twice by Silver | No duplicate rows in `silver_cve` | inserted 0 / updated 0 on the second run (S3, K2) | `evidence/s3_second_run.png` |
| NVD API unreachable during INCREMENTAL | Retries with backoff, then FAILURE row in `pipeline_execution_logs`, watermark unchanged | Observed 8 Oct 2026 exactly as expected (see finding above) | `evidence/b4_failure_logged.png` |
| BACKFILL with `end_date` before `start_date` | Rejected before any write | | |
| `02_bronze_kev` run with empty `source_path` | Refused inside the run cell, FAILURE row with `ValueError` message, no Bronze rows | Observed 8 Oct 2026, batch `20261008T142424Z-384958d6` | `evidence/pipeline_execution_logs_2026-10-08.csv` |
| INCREMENTAL pointed at a landing folder already purged by a previous success | No manifest, no dates: refused with a clear message instead of guessing a window | Observed 8 Oct 2026 (raised in the parameter cell, so not logged; see note) | |
| Record with an unknown top-level key (D4) | Kept verbatim in Bronze; flagged by known-key check; Silver loads it | `drift ['cveNewField']`; row inserted | `evidence/s4_drills.png` |
| Newer `lastModified` for an existing CVE (D1) | `MERGE` update path | `updated 1`; `last_modified_at` = 2030-01-01 | `evidence/s4_drills.png` |
| Record with no `cve_id` (D2) | Quarantined, batch continues | `missing_cve_id` row in quarantine | `evidence/s4_drills.png` |
| Unparseable `published` date (D3) | Quarantined, batch continues | `unparseable_published` row in quarantine | `evidence/s4_drills.png` |
| CVSS score sent as a string `"8.4"` (D4) | Compatible cast succeeds | `cvss_v3_score = 8.4`, `HIGH` | `evidence/s4_drills.png` |

Note on the last drill: errors raised while reading widgets, before the run cell starts, are not in
`pipeline_execution_logs` because no run was attempted. Everything from the run cell onwards is logged.

## Schema drift observed in real data

| Source | Field | Seen on | Handling |
|---|---|---|---|
| NVD CVE 2.0 | `affected` (vendor/product/version block) | Phase 1 samples, 25 Sep 2026 | Preserved in `raw_json`; listed in `NVD_CVE_KNOWN_KEYS` as known-unmodelled |
| CISA KEV | `forensicTriage` | Phase 1 sample, catalog 2026.09.24 | Added to `KEV_RECORD_SCHEMA` as STRING after the test flagged it |
| NVD CVE 2.0 | `vendorComments` | 2020 yearly feed, loaded 9 Oct 2026 | Detected at Silver run time, logged in the audit row's `schema_drift_keys`, batch completed; preserved in Bronze `raw_json` |
