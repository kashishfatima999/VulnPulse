# Phase 3 Plan: Gold Layer, BI and Final Report

> **Deadline: 24 October 2026.** Requirements: [`docs/requirements/phase3.txt`](../requirements/phase3.txt).
> Planned 16 October 2026 on branch `planning-phase3`. No code on this branch, only decisions.

## 1. What Phase 3 asks for, mapped to what we will build

| Rubric item | What we build | Owner |
|---|---|---|
| Star schema with facts and dimensions, not Silver copies | 5 dimensions, 3 facts, 1 watchlist view in `workspace.vulnpulse_gold` (section 3) | Kashish core, Zahra product and CWE arms |
| Gold data dictionary with PK/FK relationships, ER diagram | `docs/GOLD_MODEL.md` with a Mermaid `erDiagram` and column tables | Zahra |
| Performance optimisation (recommended) | Liquid clustering on facts, `OPTIMIZE`, before/after `DESCRIBE DETAIL` | Kashish |
| Gold refresh linked to the pipeline, automatic after Silver | `04_gold` notebook driven by a Gold watermark on Silver `load_timestamp`; Databricks Job chaining 01 → 02 → 03 → 04 | Kashish |
| Logging continuation with rows aggregated and execution time | `Silver-to-Gold` rows in `pipeline_execution_logs`, one per Gold table | Kashish |
| BI tool connected directly to Databricks, Gold only | Power BI Desktop → Databricks connector → Serverless Starter Warehouse, Import mode | Zahra |
| Dashboard answering the Phase 1 questions plus audit visuals, ≥3 visuals, star relationships in Model view | Two pages: Vulnerability Intelligence (5 visuals) and Pipeline Health (3 visuals) | Zahra |
| Final PDF report: architecture diagram, decision log, Spark DAG analysis, FinOps | `docs/report/VulnPulse_Phase3_Report.md` exported to PDF | Kashish drafts 1, 3, 4; Zahra drafts 2 and BI section; both review |
| Submission: repo link, `.pbix`, PDF | `bi/VulnPulse.pbix`, `docs/report/VulnPulse_Phase3_Report.pdf` | Both |

## 2. The five approved business questions and how Gold answers them

From the Phase 1 proposal, section 5 (verbatim intent):

| # | Question | Fact / dimension that answers it | Visual (proposal minimum in bold) |
|---|---|---|---|
| Q1 | How has vulnerability volume and severity changed over time? | `fact_cve` by `dim_date` (published) and `dim_severity` | **Trend line, CVE count per month by severity** |
| Q2 | Which vendors and products show up most among known-exploited vulnerabilities? | `fact_cve_product` by `dim_vendor_product`, `is_exploited` | **Bar chart, vendors ranked by total and by KEV count** |
| Q3 | Which weakness categories are most common among exploited CVEs? | `fact_cve_cwe` by `dim_cwe`, `is_exploited` | Bar chart, top CWEs among exploited CVEs |
| Q4 | How long does it take for a published CVE to be added to KEV? | `fact_cve.days_to_kev` | **Histogram of days to KEV inclusion** |
| Q5 | Which open vulnerabilities meet our watchlist criteria? | `gold_watchlist_v` over `fact_cve` and `dim_cve` | Table with severity, score, KEV status, due date |
| Audit | Is the pipeline healthy? | `pipeline_execution_logs`, `silver_quarantine` | Runs by status over time, rows per layer per run, quarantine reasons, KPI cards |

The proposal's six planned Gold tables map onto this model as follows, so the approved analytics are preserved, only the shape changes from "one aggregate per question" to "one star that answers all of them": trends → `fact_cve` × `dim_date` × `dim_severity`; vendor risk → `fact_cve_product`; KEV response → `fact_cve.days_to_kev`; CWE trends → `fact_cve_cwe`; watchlist → `gold_watchlist_v`; pipeline stats → `pipeline_execution_logs` (already built in Phase 2).

## 3. Gold dimensional model

Grain decisions first, columns second. All tables Delta in `workspace.vulnpulse_gold`. Every table carries `batch_id` (the Gold run id) and `load_timestamp` (UTC).

### Dimensions

| Table | Primary key | Grain and source | Refresh |
|---|---|---|---|
| `dim_date` | `date_key` INT `yyyymmdd` | One row per calendar day 1988-01-01 to 2030-12-31 (oldest CVE in NVD is 1988). Generated, no source | Overwrite, idempotent, built once |
| `dim_severity` | `severity_key` INT | CRITICAL, HIGH, MEDIUM, LOW, NONE, UNKNOWN with CVSS v3 score bands and sort order. Static | Overwrite, idempotent |
| `dim_cve` | `cve_id` STRING (natural key) | One row per CVE: description, vuln status, CVSS vector, `has_source_identifier`, plus KEV descriptive attributes when listed (vendor project, product name, ransomware use, required action). From `silver_cve` left join `silver_kev` | MERGE, SCD type 1 |
| `dim_vendor_product` | `vendor_product_key` BIGINT (deterministic hash of vendor + product) | One row per distinct vendor/product pair parsed from CPE criteria. From `silver_affected_product` | MERGE, SCD type 1 |
| `dim_cwe` | `cwe_key` INT (numeric part of `CWE-79`; `NVD-CWE-noinfo` = -1, `NVD-CWE-Other` = -2) | One row per weakness id seen. From `silver_cwe` | MERGE, SCD type 1 |

### Facts

| Table | Grain | Keys | Measures | Refresh |
|---|---|---|---|---|
| `fact_cve` | One row per CVE (accumulating snapshot of its lifecycle) | PK `cve_id`; FK `published_date_key`, `last_modified_date_key`, `kev_added_date_key` (nullable), `kev_due_date_key` (nullable), `severity_key` | `cvss_v3_score`, `is_exploited` (0/1), `is_ransomware` (0/1), `days_to_kev` (nullable), `product_count`, `cwe_count`, `cve_count` = 1 | MERGE on `cve_id` |
| `fact_cve_product` | One row per CVE × vendor/product | FK `cve_id`, `vendor_product_key`, `published_date_key`, `severity_key` | `is_exploited`, `cvss_v3_score` | MERGE on (`cve_id`, `vendor_product_key`) |
| `fact_cve_cwe` | One row per CVE × CWE | FK `cve_id`, `cwe_key`, `published_date_key`, `severity_key` | `is_exploited`, `cvss_v3_score` | MERGE on (`cve_id`, `cwe_key`) |

`fact_cve_product` and `fact_cve_cwe` are bridge-style facts: a CVE affecting three vendors counts once per vendor in vendor rankings, which is the correct business meaning for Q2 and Q3, while `fact_cve` keeps the one-row-per-CVE truth for Q1, Q4 and KPIs.

### View

`gold_watchlist_v`: `fact_cve` joined to `dim_cve` where `is_exploited = 1` OR (`cvss_v3_score >= 9.0` AND published within the last 90 days). Criteria from the approved ARCHITECTURE section 3.4. A view, not a table, so it is never stale.

### Relationships (what Power BI's Model view must show)

```text
dim_date (1) ──< fact_cve.published_date_key      (active)
dim_date (1) ──< fact_cve.kev_added_date_key      (inactive, used via USERELATIONSHIP for Q4)
dim_severity (1) ──< fact_cve.severity_key
dim_cve (1) ──< fact_cve.cve_id
dim_cve (1) ──< fact_cve_product.cve_id
dim_cve (1) ──< fact_cve_cwe.cve_id
dim_vendor_product (1) ──< fact_cve_product.vendor_product_key
dim_cwe (1) ──< fact_cve_cwe.cwe_key
dim_date (1) ──< fact_cve_product.published_date_key, fact_cve_cwe.published_date_key
```

### Silver additions required first (Phase 3 scope, planned since Phase 2)

| Table | Grain | Source in Bronze `raw_json` | Owner |
|---|---|---|---|
| `silver_affected_product` | One row per CVE × CPE match | `configurations[].nodes[].cpeMatch[]`: parse `cpe:2.3:part:vendor:product:...`, keep `vulnerable`, version bounds | Zahra |
| `silver_cwe` | One row per CVE × CWE id | `weaknesses[].description[].value` where lang = en | Zahra |

Same pattern as `silver_cve`: typed from `NVD_CVE_SCHEMA`, quality rules, dedup, MERGE on the composite key, `load_timestamp` and `batch_id`, audit row.

## 4. Refresh and automation design

**Incremental Gold.** `04_gold` reads a Gold watermark (`pipeline_watermarks`, source `gold_from_silver`) holding the max Silver `load_timestamp` already folded into Gold. Each run takes Silver rows with `load_timestamp` greater than that, rebuilds the affected CVE keys across all three facts and three SCD dimensions with MERGE, and advances the watermark only on success. Widget `mode = incremental | full`; `full` rebuilds every table from all of Silver and is the backfill path. Static dimensions (`dim_date`, `dim_severity`) are overwritten idempotently on every run; they are tiny.

**Linking to the pipeline.** A Databricks Job `vulnpulse_pipeline` with four tasks and job parameters: `bronze_nvd` (01) and `bronze_kev` (02) in parallel, then `silver` (03), then `gold` (04). One click or one schedule runs Bronze through Gold; a new incremental landing folder therefore refreshes Gold without any manual step. Acquisition stays on the laptop (Free Edition serverless has no outbound internet, a constraint the proposal already anticipated), so the "trigger" is: fetch, upload, run job. Evidence: the job run page with four green tasks.

**Logging.** Every Gold table write appends a `Silver-to-Gold` row to `pipeline_execution_logs`: `source` = target table, `rows_read` = Silver rows aggregated, `rows_inserted` / `rows_updated` from the MERGE, `started_at` / `finished_at` give execution time. No schema change to the log table.

**Performance.** `fact_cve`, `fact_cve_product`, `fact_cve_cwe` created with `CLUSTER BY` (liquid clustering) on `(published_date_key, severity_key)` and `(cve_id)` respectively, then `OPTIMIZE` after the full build. Evidence: `DESCRIBE DETAIL` file counts before and after, and a Power BI query timing.

## 5. BI design

- **Tool:** Power BI Desktop (free, Windows). Tableau Public cannot connect live to Databricks.
- **Connection:** Get Data → Databricks. Server hostname `dbc-98fdd24a-3295.cloud.databricks.com`, HTTP path from Serverless Starter Warehouse → Connection details. Authentication with a personal access token created under Settings → Developer → Access tokens. The token lives only in Power BI's credential store, never in the `.pbix`, never in Git.
- **Mode:** Import. Gold is under 100k rows; Import keeps the warehouse idle (FinOps) and makes the dashboard responsive. DirectQuery is the documented alternative for larger data.
- **Semantic model:** import the five dimensions, three facts, the watchlist view, `pipeline_execution_logs`, `silver_quarantine`. Set the relationships in section 3 as one-to-many, single direction. Mark `dim_date` as the date table. Screenshot of Model view is evidence.
- **Page 1, Vulnerability Intelligence:** KPI cards (total CVEs, critical count, exploited count, median days to KEV); Q1 line chart; Q2 clustered bar; Q3 bar; Q4 histogram; Q5 table. Slicers: year, severity, vendor.
- **Page 2, Pipeline Health:** runs by status over time (stacked column), rows read/inserted/updated per run per layer (table), quarantine reasons (bar), KPI cards (last run status, last watermark, failure count).
- **Deliverable:** `bi/VulnPulse.pbix` committed (expected 2 to 8 MB), plus `docs/evidence/bi_page1.png`, `bi_page2.png`, `bi_model_view.png`, and a PDF export of both pages for reviewers without Power BI.

## 6. Report outline (`docs/report/VulnPulse_Phase3_Report.md` → PDF)

1. Executive summary and architecture diagram (source → laptop acquisition → landing volume → Bronze → Silver → Gold → Power BI).
2. Data models: Bronze and Silver (from README), Gold star schema with ER diagram (from `GOLD_MODEL.md`).
3. Decision log (section 7 below, expanded with outcomes).
4. Spark execution analysis: query profile DAG of the `fact_cve_product` build (join of `silver_affected_product` to `silver_cve` and `silver_kev`, then MERGE), explaining scans, broadcast or shuffle joins, exchanges, predicate pushdown on the watermark filter, and the MERGE's file rewrite.
5. FinOps: measured durations per run from `pipeline_execution_logs`, assumed serverless DBU rate, cost of a daily incremental, projection for hourly runs over a year, and optimisations (incremental over full, clustering, warehouse auto-stop, Import mode, scheduling off-peak, right-sizing).
6. Evidence index: links to `docs/EVIDENCE.md`, HTML exports, video, job run.
7. Team contribution table.

Authored in Markdown in the repo for a single source of truth, exported to PDF with a browser print or Pandoc at the end.

## 7. Decision log and judgment calls

| # | Decision | Alternatives considered | Why | Classification |
|---|---|---|---|---|
| D1 | Star schema, not snowflake | Snowflake with `dim_vendor` → `dim_product`; one wide aggregate per question (the Phase 1 sketch) | Power BI performs best on a star; our dimensions are small and one level deep; the rubric asks for facts and dimensions explicitly | REQUIRED |
| D2 | Three facts: CVE grain plus two bridge facts (product, CWE) | One fact with vendor as an attribute (wrong: a CVE has many vendors); one fact at CVE × product grain only (inflates CVE counts) | Q1/Q4 need one row per CVE; Q2/Q3 need per-vendor and per-CWE counts without double counting CVE totals | REQUIRED |
| D3 | Natural key `cve_id` as PK of `dim_cve` and FK in facts; integer `date_key`; hash surrogate for vendor/product | Surrogate integer keys everywhere | `cve_id` is stable, unique and human-readable; surrogates only where the natural key is composite (vendor + product). Simpler Power BI relationships. **Outcome 16 Oct:** keys also declared as informational PK/FK constraints in Unity Catalog; all 8 PKs and 14 FKs were accepted on Free Edition (G1), so the relationships are visible in Catalog Explorer, not only in docs | RECOMMENDED |
| D4 | All Gold writes are MERGE (SCD1 for dims, upsert for facts), driven by a Gold watermark on Silver `load_timestamp`; `mode=full` for rebuilds | Overwrite everything on every run | Overwrite is simple but breaks the Phase 2 idempotency story and costs a full rebuild per incremental; watermark-driven MERGE processes only what changed | REQUIRED (rubric: refresh via MERGE or overwrite, we choose MERGE) |
| D5 | Orchestration with a Databricks Job (four tasks) rather than `dbutils.notebook.run` chains inside notebooks | Calling `04_gold` from the end of `03_silver` | A Job is declarative, parameterised, schedulable, and produces a run page as evidence; notebooks stay independently runnable for backfills. **Outcome 17 Oct:** `vulnpulse_pipeline` ran green in 4 min 48 s (G4). A second run pointed at the already-consumed landing folders failed cleanly at Bronze and skipped Silver and Gold (G4b), which confirms both the purge-after-success rule and the dependency wiring. Consequence for operations: each run must receive its landing path as a run parameter | REQUIRED |
| D6a | `OPTIMIZE` is run as an explicit maintenance step (`optimize = yes` widget), not on every refresh | Optimise inside every run | Measured on 17 Oct: `fact_cve` was already a single 0.27 MB file after four MERGEs, so `OPTIMIZE` changed nothing (G5). Running it every time would burn compute for no gain at this scale; the method and the clustering keys are in place for when the tables grow | RECOMMENDED |
| D6 | No partitioning; liquid clustering on facts | Partition by `year(published_at)` as FINOPS.md suggested in Phase 1 | Largest fact is well under a million rows; Hive-style partitions would create many tiny files and slow reads. Liquid clustering gives data skipping without that cost. This answers the rubric's "why your partition columns" question honestly: we measured, and chose not to partition | RECOMMENDED |
| D7 | Logging reuses `pipeline_execution_logs` unchanged; `rows_read` is the rows aggregated, duration = `finished_at - started_at` | Add `rows_aggregated` and `duration_seconds` columns | Avoids a schema migration on a table two layers already write; the values the rubric asks for are present or derivable | REQUIRED |
| D8 | Power BI Import mode over a SQL warehouse, token stored only in Power BI | DirectQuery; Databricks AI/BI dashboards | Import is fast and spends no warehouse time while people browse; native Databricks dashboards do not satisfy "connect Power BI or Tableau" | REQUIRED |
| D9 | Spark execution analysis from the serverless query profile plus `EXPLAIN FORMATTED` | Classic Spark UI | Free Edition serverless does not expose the classic Spark UI; the query profile shows the same DAG (scans, exchanges, joins) and is the honest artefact | REQUIRED (adapted) |
| D10 | FinOps from measured durations in the log table and a stated DBU price assumption | Guess | Free Edition shows no bill, so cost is modelled: duration × assumed DBU/h × $/DBU, with the assumption written down | REQUIRED |
| D11 | `silver_affected_product` and `silver_cwe` built now with the Phase 2 Silver pattern | Parse CPE and CWE directly in Gold from `raw_json` | Gold must not parse raw JSON; Silver is where typing and quality live. These two tables were deferred from Phase 2 by design | REQUIRED |
| D12 | PII rule unchanged: `sourceIdentifier` never reaches Gold or Power BI | Hash it for lineage | Analytics never needs it; `has_source_identifier` already carries the lineage signal | REQUIRED |
| D13 | Report written as Markdown in the repo and exported to PDF | Write directly in Word or Google Docs | One source, reviewable in PRs, diagrams rendered from Mermaid, no copy drift | RECOMMENDED |
| D14 | `.pbix` committed to `bi/`, plus PNG and PDF exports of the pages | Published link only | Rubric accepts the file; exports let a reviewer without Power BI see the dashboard | REQUIRED |

## 8. Risks and mitigations

| Risk | Mitigation |
|---|---|
| CPE parsing is fiddly (escaped colons, wildcards) | Unit-test the parser on the ten-record sample first; quarantine unparseable criteria with a reason, never crash |
| Power BI Desktop is Windows-only; whoever builds the dashboard needs Windows | Confirm on day 1. If Zahra is not on Windows, swap: Kashish builds the dashboard, Zahra takes the Job and clustering work |
| PAT creation unavailable or warehouse quota on Free Edition | Try on day 1. Fallback: OAuth in the Databricks connector; last resort: export Gold to CSV for Import mode and document why |
| Serverless query profile looks different from a classic Spark UI | Capture it early (day 4) and write the explanation against what it shows; include `EXPLAIN FORMATTED` text |
| Free Edition fair-use quota during repeated Gold rebuilds | Build on the current 22k-CVE Silver, no new yearly feeds; one full rebuild per day maximum |
| Two people editing the report | Sections owned per the table in section 1; merge the report last, on 22 October |

## 9. Schedule, 16 to 24 October

| Day | Kashish | Zahra |
|---|---|---|
| Thu 16 | Plan merged. `gold` package skeleton, `dim_date`, `dim_severity`, DDL with clustering | Read plan. Design `silver_affected_product` and `silver_cwe` (schemas, keys, quality rules). Confirm Power BI Desktop installs |
| Fri 17 | `dim_cve`, `fact_cve` (days to KEV, flags), Silver-to-Gold logging | `silver_affected_product` and `silver_cwe` built, tested on the sample, run in Databricks |
| Sat 18 | Gold watermark and incremental mode, `04_gold` notebook end to end on current Silver | `dim_vendor_product`, `dim_cwe`, `fact_cve_product`, `fact_cve_cwe` with tests |
| Sun 19 | Databricks Job with four tasks, one green run; `OPTIMIZE` evidence | `docs/GOLD_MODEL.md` with ER diagram and dictionary; Power BI connection and import working |
| Mon 20 | Query profile capture and DAG write-up; FinOps numbers from the log table | Dashboard page 1, five visuals, Model view relationships |
| Tue 21 | Report sections 1, 4, 5; architecture diagram; README Gold section and run guide | Dashboard page 2 (audit), slicers, screenshots, `.pbix` committed |
| Wed 22 | Report assembly, decision log outcomes | Report section 2 and BI section; review Kashish's PR |
| Thu 23 | Freeze. Final job run, EVIDENCE.md, PDF export, both PRs merged | Same |
| Fri 24 | Submit | Submit |

## 10. Definition of done for Phase 3

1. Nine Gold objects exist in `workspace.vulnpulse_gold` with the keys in section 3, every row carrying `batch_id` and `load_timestamp`.
2. The Job `vulnpulse_pipeline` has at least one fully green run after an incremental landing folder, and the run page is in `docs/evidence/`.
3. `pipeline_execution_logs` contains `Silver-to-Gold` rows for every Gold table with rows read, inserted, updated and timings.
4. `bi/VulnPulse.pbix` opens, Model view shows the star relationships, both pages render, and the dashboard reads Gold only.
5. `docs/report/VulnPulse_Phase3_Report.pdf` contains the diagram, decision log, query profile analysis and FinOps section.
6. README has a Phase 3 section with the Gold dictionary link, the job run guide and the BI connection guide; CI green on `main`.
