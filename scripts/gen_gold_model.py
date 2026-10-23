#!/usr/bin/env python3
"""Generate docs/GOLD_MODEL.md from src/vulnpulse/gold/ddl.py.

The ER diagram and the column tables are derived from ``TABLES`` and ``FOREIGN_KEYS``, so the
document cannot drift from the code. Re-run after any change to ddl.py:

    python scripts/gen_gold_model.py > docs/GOLD_MODEL.md
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from vulnpulse.gold.ddl import FOREIGN_KEYS, TABLES, WATCHLIST_VIEW  # noqa: E402

_MERMAID_TYPE = {"bigint": "bigint", "int": "int", "string": "string", "double": "double"}

# What each column means, for the data dictionary. Columns not listed get no description.
DESCRIPTIONS = {
    "date_key": "yyyymmdd integer, e.g. 20261023",
    "full_date": "Calendar date",
    "year_month": "'2026-10'",
    "day_of_week": "1 = Monday .. 7 = Sunday",
    "severity_key": "1 CRITICAL, 2 HIGH, 3 MEDIUM, 4 LOW, 5 NONE, 6 UNKNOWN",
    "severity": "CVSS v3 severity band",
    "score_min": "Lowest CVSS v3 score in the band",
    "score_max": "Highest CVSS v3 score in the band",
    "sort_order": "Display order, most severe first",
    "cve_id": "NVD identifier, e.g. CVE-2024-3400 (natural key)",
    "description_en": "English description",
    "vuln_status": "NVD analysis status (Analyzed, Modified, ...)",
    "cvss_vector": "CVSS v3 vector string",
    "has_source_identifier": "Submitter identifier was present (the identifier itself is PII, never stored)",
    "is_in_kev": "Listed in CISA KEV",
    "kev_vendor_project": "Vendor as named by CISA",
    "kev_product": "Product as named by CISA",
    "kev_vulnerability_name": "CISA vulnerability title",
    "known_ransomware_campaign_use": "Known | Unknown",
    "kev_required_action": "CISA remediation instruction",
    "kev_due_date": "Federal remediation deadline",
    "vendor_product_key": "xxhash64(lower(trim(vendor)) | lower(trim(product)))",
    "vendor": "CPE vendor, lower-cased",
    "product": "CPE product, lower-cased",
    "part": "CPE part: a = application, o = operating system, h = hardware",
    "cwe_key": "Numeric part of CWE-n; -1 = NVD-CWE-noinfo; -2 = NVD-CWE-Other",
    "cwe_id": "CWE-79, NVD-CWE-noinfo, NVD-CWE-Other",
    "cwe_category": "CWE | NVD-CWE-noinfo | NVD-CWE-Other",
    "published_date_key": "FK dim_date: NVD publication date",
    "last_modified_date_key": "FK dim_date: last NVD modification",
    "kev_added_date_key": "FK dim_date: date added to KEV (NULL if not listed)",
    "kev_due_date_key": "FK dim_date: KEV due date (NULL if not listed)",
    "cvss_v3_score": "CVSS v3 base score (v3.1 preferred, else v3.0)",
    "is_exploited": "1 if in CISA KEV else 0 (summable)",
    "is_ransomware": "1 if KEV lists known ransomware use else 0",
    "days_to_kev": "Days from NVD publication to KEV listing",
    "product_count": "Affected vendor/products (rows in fact_cve_product)",
    "cwe_count": "Weaknesses (rows in fact_cve_cwe)",
    "cve_count": "Always 1, so COUNT becomes SUM in BI",
    "batch_id": "Gold run id that last wrote the row",
    "load_timestamp": "UTC time the row was last written",
}


def mermaid() -> list[str]:
    lines = ["```mermaid", "erDiagram"]
    for fk in FOREIGN_KEYS:
        label = fk.column + ("" if fk.active_in_bi else " (inactive in BI)")
        lines.append(f'    {fk.ref_table} ||--o{{ {fk.table} : "{label}"')
    for t in TABLES.values():
        fk_cols = {fk.column for fk in FOREIGN_KEYS if fk.table == t.name}
        lines.append(f"    {t.name} {{")
        for f in t.schema.fields:
            typ = _MERMAID_TYPE.get(f.dataType.simpleString(), f.dataType.simpleString())
            marks = []
            if f.name in t.primary_key:
                marks.append("PK")
            if f.name in fk_cols:
                marks.append("FK")
            lines.append(f"        {typ} {f.name} {','.join(marks)}".rstrip())
        lines.append("    }")
    lines.append("```")
    return lines


def table_section(name: str) -> list[str]:
    t = TABLES[name]
    fks = {fk.column: fk for fk in FOREIGN_KEYS if fk.table == name}
    out = [
        f"### `{name}` ({t.kind})",
        "",
        f"{t.comment}. Primary key: `({', '.join(t.primary_key)})`."
        + (f" Liquid clustering: `{', '.join(t.cluster_by)}`." if t.cluster_by else ""),
        "",
        "| Column | Type | Null | Key | Description |",
        "|---|---|---|---|---|",
    ]
    for f in t.schema.fields:
        key = []
        if f.name in t.primary_key:
            key.append("PK")
        if f.name in fks:
            key.append(f"FK → {fks[f.name].ref_table}.{fks[f.name].ref_column}")
        out.append(
            f"| `{f.name}` | {f.dataType.simpleString().upper()} | "
            f"{'yes' if f.nullable else 'no'} | {', '.join(key)} | {DESCRIPTIONS.get(f.name, '')} |"
        )
    out.append("")
    return out


def main() -> None:
    dims = [n for n, t in TABLES.items() if t.kind == "dimension"]
    facts = [n for n, t in TABLES.items() if t.kind == "fact"]
    doc = [
        "# Gold Data Model: VulnPulse Star Schema",
        "",
        "> Generated from [`src/vulnpulse/gold/ddl.py`](../src/vulnpulse/gold/ddl.py) by",
        "> `python scripts/gen_gold_model.py > docs/GOLD_MODEL.md`. Do not edit by hand.",
        "",
        "All tables are Delta in `workspace.vulnpulse_gold`, created idempotently by `notebooks/04_gold`,",
        "with informational PRIMARY KEY / FOREIGN KEY constraints in Unity Catalog. Every row carries",
        "`batch_id` (Gold run id) and `load_timestamp` (UTC). Dimensions are SCD type 1 (MERGE),",
        "facts are MERGE upserts on their primary key; `dim_date` and `dim_severity` are generated.",
        "",
        f"**{len(dims)} dimensions:** " + ", ".join(f"`{d}`" for d in dims) + ".  ",
        f"**{len(facts)} facts:** " + ", ".join(f"`{f}`" for f in facts) + ".  ",
        f"**1 view:** `{WATCHLIST_VIEW}` (exploited, or CVSS ≥ 9.0 and published in the last 90 days).",
        "",
        "## Entity-relationship diagram",
        "",
        "Every relationship is one-to-many from the dimension to the fact. `dim_date` plays four roles",
        "for `fact_cve`; Power BI allows one active relationship per table pair, so `published` is active",
        "and the other three are used with `USERELATIONSHIP`.",
        "",
        *mermaid(),
        "",
        "## Why three facts",
        "",
        "`fact_cve` is one row per CVE, the grain for counts, trends and days-to-KEV (Q1, Q4, KPIs).",
        "A CVE affects many products and can have several weaknesses, so vendor and weakness rankings",
        "(Q2, Q3) use the bridge facts `fact_cve_product` (CVE × vendor/product) and `fact_cve_cwe`",
        "(CVE × CWE). Each bridge row repeats the CVE's `published_date_key`, `severity_key`,",
        "`cvss_v3_score` and `is_exploited`, derived with the same key expressions as `fact_cve`, so",
        "date, severity and KEV slicers filter all three facts consistently without double-counting",
        "CVE totals.",
        "",
        "## Relationships",
        "",
        "| Fact column | Dimension | Role | Active in Power BI |",
        "|---|---|---|---|",
    ]
    for fk in FOREIGN_KEYS:
        doc.append(
            f"| `{fk.table}.{fk.column}` | `{fk.ref_table}.{fk.ref_column}` | {fk.role or '-'} | "
            f"{'yes' if fk.active_in_bi else 'no'} |"
        )
    doc += ["", "## Data dictionary", "", "### Dimensions", ""]
    for d in dims:
        doc += table_section(d)
    doc += ["### Facts", ""]
    for f in facts:
        doc += table_section(f)
    doc += [
        "## Lineage",
        "",
        "| Gold table | Built from (Silver) | Builder |",
        "|---|---|---|",
        "| `dim_date`, `dim_severity` | generated | `gold/dims_static.py` |",
        "| `dim_cve`, `fact_cve` | `silver_cve` ⟕ `silver_kev`; counts from the bridge facts | `gold/cve.py` |",
        "| `dim_vendor_product`, `fact_cve_product` | `silver_affected_product` (vulnerable = true) "
        "⋈ `silver_cve` ⟕ `silver_kev` | `gold/products.py` |",
        "| `dim_cwe`, `fact_cve_cwe` | `silver_cwe` ⋈ `silver_cve` ⟕ `silver_kev` | `gold/cwe.py` |",
        "",
    ]
    print("\n".join(doc))


if __name__ == "__main__":
    main()
