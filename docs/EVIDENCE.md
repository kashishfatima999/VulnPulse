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
