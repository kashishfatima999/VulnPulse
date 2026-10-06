# VulnPulse Project Contract

Hard rules for every piece of code in this repository, whether written by a person or generated
by an AI assistant. Paste this file into any AI prompt before asking for code. A pull request
that breaks one of these rules is not mergeable, even if it runs.

## Schemas and types

1. Never use `inferSchema`. Every read of JSON, CSV or API output passes an explicit `StructType`.
2. Schemas live in `src/vulnpulse/schemas/` and nowhere else. Notebooks import them.
3. Every timestamp is stored as `TimestampType` in UTC. Strings from the source are parsed, not kept.

## Bronze

4. Bronze is append-only and preserves the raw payload as a string column (`raw_json`).
5. Every Bronze row carries `batch_id`, `load_type`, `source_uri`, `load_timestamp`, `payload_sha256`.
   Every Silver row carries `load_timestamp` and `batch_id` too (rubric: metadata on every record).
6. `load_type` is one of `FULL`, `INCREMENTAL`, `BACKFILL`. Nothing else.

## Silver

7. Silver writes go through `MERGE INTO` keyed on the natural key (`cve_id`, or `cve_id` plus the
   child key). Running the same Bronze batch twice must leave Silver unchanged.
8. Deduplicate on the key before the MERGE, keeping the row with the latest `last_modified_at`.
9. A record that cannot be made to conform goes to `silver_quarantine` with a `reason`. The batch
   continues. A bad row never aborts a run.
10. `sourceIdentifier` is never stored in Silver or Gold. Only `has_source_identifier` (boolean).

## Parameters and runs

11. No hardcoded dates, years, paths or table names inside functions. They arrive as parameters
    (notebook widgets or job parameters) and are read in one place.
12. The incremental window comes from the stored watermark, with a 10-minute overlap. A backfill
    passes explicit `start_date` and `end_date` and does not move the watermark.
13. The watermark is advanced only after the batch has succeeded.

## Audit

14. Every run writes one row to `pipeline_execution_logs`: layer (Raw-to-Bronze, Bronze-to-Silver),
    source/parameter processed, load_type, batch_id, start/end time (UTC), status,
    records_read, records_written, and an error message when it failed.
15. Every Silver MERGE records inserted, updated, rejected and quarantined counts.

## Security and repository hygiene

16. No API keys, tokens or passwords in code, notebooks, config files or commit messages. Use
    Databricks secrets or job parameters.
17. No raw datasets, Delta files, Parquet or `.gz` archives in Git. Only the ten-record samples in
    `data/`.
18. All logic lives in `src/vulnpulse/`. Notebooks read parameters, call functions, display results.
19. `ruff check .`, `ruff format --check .` and `pytest` pass before a PR is opened.
20. Work on your own branch. `main` changes only through a reviewed pull request with green CI.
