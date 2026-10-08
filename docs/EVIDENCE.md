# Phase 2 Run Evidence

Proof that the pipeline behaves as the rubric requires, collected from real runs in Databricks.
Screenshots live in `docs/evidence/` (PNG, under 500 KB each). Audit table exports live there too as
CSV, so they can be read and diffed without opening images.

Exports so far:

| File | Content |
|---|---|
| `evidence/pipeline_execution_logs_2026-10-08.csv` | Every Raw-to-Bronze run up to the end of 8 Oct 2026: 4 sample FULL loads, 1 INCREMENTAL (862 rows), 1 BACKFILL (708 rows), 1 KEV FULL (1,734 rows), 2 logged failures |

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
| B4b | INCREMENTAL again | Window starts at watermark minus 10 min; watermark advances; small or zero row count | | |
| B5 | `01_bronze_nvd` BACKFILL for 2026-10-01 to 2026-10-02 (708 records) | Explicit window processed from the manifest; watermark table still exactly one row (`13:28:04Z`) afterwards | Done 8 Oct 2026, batch `20261008T133347Z-a8a9241c` | `evidence/pipeline_execution_logs_2026-10-08.csv` |
| B6 | `02_bronze_kev` from an uploaded landing folder (catalog 2026.10.04, 1,734 entries) | Second source, catalog version lifted, manifest batch id reused | Done 8 Oct 2026, batch `20261008T133204Z-097ea6cd` | `evidence/pipeline_execution_logs_2026-10-08.csv` |
| B3 | `01_bronze_nvd` FULL on one real yearly feed from the landing volume | Baseline load at real volume; landing file purged after success | | |

## Silver milestones (Zahra)

All runs on 8 Oct 2026 in `notebooks/03_silver`, serverless, against the Bronze state above
(NVD: 40 FULL + 862 INCREMENTAL + 708 BACKFILL = 1,610 rows, 1,580 distinct CVEs; KEV: 1,734 rows).

| # | Run | What it proves | Observed | Evidence |
|---|---|---|---|---|
| S1 | Silver DDL (`ddl.ensure_tables`), run twice | Explicit types and keys, `load_timestamp` and `batch_id` on every table; DDL is re-runnable | 3 tables created; second run no-op; `DESCRIBE` shows TIMESTAMP / DOUBLE / BOOLEAN columns | `evidence/s1_silver_ddl.png` |
| S1b | Transform preview over all Bronze | Casting and flattening | 1,610 rows, 1,580 distinct CVEs, 0 null ids / published / last_modified, 159 null v3 scores (v2-only or unscored CVEs), 0 drift keys | `evidence/s1b_transform_preview.png` |
| S2 | `03_silver` NVD, first run | Dedup + `MERGE INTO` | read 1,610, inserted 1,580, updated 0, quarantined 0; `silver_cve` 1,580 rows = 1,580 distinct | `evidence/s2_first_run.png` |
| S3 | Same run again, same Bronze | Idempotency | read 1,610, **inserted 0, updated 0**, quarantined 0; still 1,580 rows | `evidence/s3_second_run.png` |
| K1 | `03_silver` KEV, first run | Second source through the same path | read 1,734, inserted 1,734, updated 0, quarantined 0; dates 2021-11-03 to 2026-10-04 | `evidence/k1_kev_first_run.png` |
| K2 | KEV again | Idempotency | **inserted 0, updated 0**, quarantined 0 | `evidence/k2_kev_second_run.png` |

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

## Failure drills

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
