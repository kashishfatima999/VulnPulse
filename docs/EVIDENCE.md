# Phase 2 Run Evidence

Proof that the pipeline behaves as the rubric requires, collected from real runs in Databricks.
Screenshots live in `docs/evidence/` (PNG, under 500 KB each). Audit rows are pasted as text so they
can be read without opening images.

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
| B4 | `01_bronze_nvd` INCREMENTAL, first run (no watermark) | 24-hour seed window, API pagination, watermark created | | |
| B4b | INCREMENTAL again | Window starts at watermark minus 10 min; watermark advances; small or zero row count | | |
| B5 | `01_bronze_nvd` BACKFILL for 2026-10-01 to 2026-10-02 | Explicit window processed; watermark table unchanged | | |
| B6 | `02_bronze_kev` live snapshot | Second source, ~1,750 rows, catalog version lifted | | |
| B3 | `01_bronze_nvd` FULL on one real yearly feed from the landing volume | Baseline load at real volume; landing file purged after success | | |

## Silver milestones (Zahra)

| # | Run | What it proves | Status | Evidence |
|---|---|---|---|---|
| S1 | Silver DDL | Explicit types and keys, `load_timestamp` on every table | | |
| S2 | `03_silver` on Bronze after B1 | Casting, flattening, `MERGE INTO`, `inserted=10, updated=0` | | |
| S3 | `03_silver` again on the same Bronze batches | Idempotency: Silver unchanged, `inserted=0, updated=0` | | |
| S4 | Injected bad rows (string CVSS, missing id) | Compatible cast succeeds; non-conforming row quarantined; batch succeeds | | |
| S5 | Bronze row with newer `lastModified` for an existing CVE | `MERGE` update path, `updated=1` | | |

## Failure drills

| Drill | Expected | Observed | Evidence |
|---|---|---|---|
| Same Bronze batch processed twice by Silver | No duplicate rows in `silver_cve` | | |
| NVD API unreachable during INCREMENTAL | Retries with backoff, then FAILURE row in `pipeline_execution_logs`, watermark unchanged | | |
| BACKFILL with `end_date` before `start_date` | Rejected before any write | | |
| Record with an unknown top-level key | Kept verbatim in Bronze; flagged by known-key check; Silver ignores or quarantines | | |

## Schema drift observed in real data

| Source | Field | Seen on | Handling |
|---|---|---|---|
| NVD CVE 2.0 | `affected` (vendor/product/version block) | Phase 1 samples, 25 Sep 2026 | Preserved in `raw_json`; listed in `NVD_CVE_KNOWN_KEYS` as known-unmodelled |
| CISA KEV | `forensicTriage` | Phase 1 sample, catalog 2026.09.24 | Added to `KEV_RECORD_SCHEMA` as STRING after the test flagged it |
