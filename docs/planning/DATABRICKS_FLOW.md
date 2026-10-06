# Databricks Flow for Phase 2

Who does what, in which order, inside Databricks Free Edition. Pair this with
[`WORK_DIVISION.md`](WORK_DIVISION.md). Local development happens in VS Code; Databricks is
where Spark, Delta and the real pipeline run.

Free Edition facts that shape this plan:

- Compute is **serverless only**. There is no cluster to create or manage.
- Unity Catalog is on. The default catalog is `workspace`.
- Fair-use quotas exist. Iterate on ten-record samples; run big loads once, deliberately.
- Git folders are supported. **Each person creates their own Git folder** of the same repo.

---

## Stage 0: both of you, Day 1

| Step | Where | What | Done when |
|---|---|---|---|
| 0.1 | GitHub | Add a branch ruleset on `main`: require PR, require the three CI checks, 1 approval | Direct push to `main` is rejected |
| 0.2 | Databricks → Settings → Linked accounts | Link GitHub. Choose the **GitHub App** option if offered, and grant it access to **only the VulnPulse repository**. Otherwise use a **fine-grained personal access token** scoped to that one repo with `Contents: read/write` and `Metadata: read` | Linked account shows GitHub |
| 0.3 | Databricks → Workspace → Users → you → Create → Git folder | Paste the repo URL. Name it `VulnPulse` | Folder appears with `README.md`, `docs/`, `tests/` |
| 0.4 | Git folder → branch dropdown | Switch to your own branch (`phase2-kashish` / `phase2-zahra`). Never work on `main` here | Branch name shows in the folder header |
| 0.5 | Any notebook | Attach to Serverless, run `print(spark.version)` | Prints a version. Compute works |

Test the Git connection: edit nothing, click **Pull** in the Git folder. If it pulls without an
auth error, the token works.

---

## Stage 1: Kashish, workspace layout

Run once from `notebooks/00_setup_catalog.py`. All names come from ARCHITECTURE.md.

```sql
CREATE SCHEMA IF NOT EXISTS workspace.vulnpulse_bronze;
CREATE SCHEMA IF NOT EXISTS workspace.vulnpulse_silver;
CREATE SCHEMA IF NOT EXISTS workspace.vulnpulse_gold;
CREATE VOLUME IF NOT EXISTS workspace.vulnpulse_bronze.landing;
```

| Object | Purpose |
|---|---|
| `workspace.vulnpulse_bronze.landing` (volume) | Where downloaded `nvdcve-2.0-YYYY.json.gz` files and API pages land before Bronze reads them. Purged after a successful load (FinOps rule). |
| `workspace.vulnpulse_bronze.bronze_nvd_raw` | Raw NVD pages, one row per file or API page |
| `workspace.vulnpulse_bronze.bronze_cisa_raw` | Raw KEV snapshots |
| `workspace.vulnpulse_silver.*` | Zahra's tables (created by her DDL module, called from the same setup notebook) |
| `workspace.vulnpulse_gold.gold_pipeline_audit` | Run audit + watermark. Both of you append to it |

NVD API key: optional (it only raises the rate limit). If you use one, store it as a Databricks
secret or pass it as a job parameter. It never appears in code or in Git.

---

## Stage 2: Kashish, Bronze loop

```
VS Code                         GitHub                    Databricks Git folder
write src/vulnpulse/...  ──►  push phase2-kashish  ──►  Pull
pytest locally                                          run notebooks/01_bronze_nvd.py
                                                        with widget load_type=FULL, year=2026
                                                        (tiny: point at data/ sample first)
      ◄──────────────── paste error to Claude ◄────────  fails?
```

Notebook `01_bronze_nvd.py` is thin, about 30 lines:

1. `dbutils.widgets` for `load_type`, `year`, `start_date`, `end_date`, `batch_id`.
2. `from vulnpulse.ingestion ... import ...` (the Git folder root is on `sys.path`).
3. Call the reader, call the Bronze writer, call the audit writer.
4. `display()` the audit row and `SELECT count(*)` from the Bronze table.

Order of Bronze milestones in Databricks:

| # | Run | Expect |
|---|---|---|
| B1 | `load_type=FULL` reading `data/nvd_full_load_sample.json` from the Git folder | 1 row in `bronze_nvd_raw`, audit row `status=SUCCESS, records_read=10` |
| B2 | Same run again with a new `batch_id` | 2 rows in Bronze (Bronze is append-only; dedup is Silver's job), same `payload_sha256` on both |
| B3 | `load_type=FULL, year=2026` real feed into the volume | Audit row with real counts, volume file removed after load |
| B4 | `load_type=INCREMENTAL` with no dates | Reads watermark, queries API with 10-minute overlap, writes new watermark |
| B5 | `load_type=BACKFILL, start_date, end_date` | Same code path as B4 with explicit window, watermark untouched |
| B6 | KEV snapshot via `02_bronze_kev.py` | 1 row per run in `bronze_cisa_raw` with `catalog_version` |

---

## Stage 3: Zahra, Silver loop

Zahra does not wait for Bronze. Local tests build a fake Bronze DataFrame from the samples.
In Databricks she needs only one real Bronze row, which exists after Kashish's B1.

| # | Run | Expect |
|---|---|---|
| S1 | `00_setup_catalog.py` Silver section | Five empty Silver tables + `silver_quarantine` |
| S2 | `03_silver.py` on Bronze after B1 | 10 rows in `silver_cve`, child tables populated, audit row `inserted=10, updated=0` |
| S3 | `03_silver.py` again on Bronze after B2 (same payload twice) | Silver still 10 rows, audit `inserted=0, updated=0` |
| S4 | Inject a Bronze row whose `cvss_score` is a string and one missing `id` | String casts fine; row without `id` lands in `silver_quarantine`; batch succeeds |
| S5 | Bronze row with a newer `lastModified` for an existing CVE | `silver_cve` row updated, audit `updated=1` |

---

## Stage 4: both, integration and job

1. Kashish runs B3 (one real year). Zahra runs S2 on it. Compare `count(distinct cve_id)` in
   Silver to `totalResults` in the feed.
2. Run the failure drills from WORK_DIVISION.md and record outcomes in `docs/EVIDENCE.md`.
3. Kashish creates a **Job** (Workflows → Jobs → Create): task 1 = `01_bronze_nvd.py` with
   `load_type=INCREMENTAL`, task 2 = `02_bronze_kev.py`, task 3 = `03_silver.py` depending on
   both. Schedule: daily. Leave it **paused** until the final week so quota is not burned, then
   let it run at least once scheduled and keep the run page as evidence.
4. Final: both branches merged to `main`, CI green, both Git folders pulled to `main`, one
   clean end-to-end job run.

---

## Rules that save you quota and pain

- Never run anything bigger than one year in Databricks until Stage 4.
- Never fix code inside the Databricks notebook editor and forget to commit. Commit from the Git
  folder, then `git pull` locally, so the VS Code copy and Claude see it.
- Never both click Git buttons in the same Git folder. One folder per person.
- Always `Pull` before you run. Always run on ten records before you run on a year.
