"""Gold star schema: table definitions, keys, clustering and idempotent DDL.

This file is the contract between the two halves of Phase 3. Column names and keys declared here
are what every builder writes and what Power BI's model mirrors. Change it only through a PR both
teammates review.

Grain summary (see docs/planning/PHASE3_PLAN.md section 3):

    dim_date            one row per calendar day 1988..2030          PK date_key
    dim_severity        one row per CVSS v3 severity band            PK severity_key
    dim_cve             one row per CVE, descriptive + KEV attrs     PK cve_id
    dim_vendor_product  one row per vendor/product from CPE          PK vendor_product_key
    dim_cwe             one row per weakness id                      PK cwe_key
    fact_cve            one row per CVE (lifecycle snapshot)         PK cve_id
    fact_cve_product    one row per CVE x vendor/product             PK (cve_id, vendor_product_key)
    fact_cve_cwe        one row per CVE x CWE                        PK (cve_id, cwe_key)
    gold_watchlist_v    view over fact_cve + dim_cve
"""

from __future__ import annotations

from dataclasses import dataclass, field

from pyspark.sql import SparkSession
from pyspark.sql.types import (
    BooleanType,
    DateType,
    DoubleType,
    IntegerType,
    LongType,
    StringType,
    StructField,
    StructType,
    TimestampType,
)

# ---------------------------------------------------------------------------------------------
# Audit columns every Gold table carries (contract rule 22)
# ---------------------------------------------------------------------------------------------

_AUDIT = [
    StructField("batch_id", StringType(), nullable=False),
    StructField("load_timestamp", TimestampType(), nullable=False),
]

# ---------------------------------------------------------------------------------------------
# Dimensions
# ---------------------------------------------------------------------------------------------

DIM_DATE_SCHEMA = StructType(
    [
        StructField("date_key", IntegerType(), nullable=False),  # yyyymmdd
        StructField("full_date", DateType(), nullable=False),
        StructField("year", IntegerType(), nullable=False),
        StructField("quarter", IntegerType(), nullable=False),
        StructField("month", IntegerType(), nullable=False),
        StructField("month_name", StringType(), nullable=False),
        StructField("year_month", StringType(), nullable=False),  # '2026-10'
        StructField("day", IntegerType(), nullable=False),
        StructField("day_of_week", IntegerType(), nullable=False),  # 1 = Monday .. 7 = Sunday
        StructField("day_name", StringType(), nullable=False),
        StructField("week_of_year", IntegerType(), nullable=False),
        StructField("is_weekend", BooleanType(), nullable=False),
        *_AUDIT,
    ]
)

DIM_SEVERITY_SCHEMA = StructType(
    [
        StructField("severity_key", IntegerType(), nullable=False),
        StructField("severity", StringType(), nullable=False),  # CRITICAL .. UNKNOWN
        StructField("score_min", DoubleType()),
        StructField("score_max", DoubleType()),
        StructField("sort_order", IntegerType(), nullable=False),
        StructField("description", StringType()),
        *_AUDIT,
    ]
)

DIM_CVE_SCHEMA = StructType(
    [
        StructField("cve_id", StringType(), nullable=False),
        StructField("description_en", StringType()),
        StructField("vuln_status", StringType()),
        StructField("cvss_vector", StringType()),
        StructField("has_source_identifier", BooleanType()),
        StructField("is_in_kev", BooleanType(), nullable=False),
        StructField("kev_vendor_project", StringType()),
        StructField("kev_product", StringType()),
        StructField("kev_vulnerability_name", StringType()),
        StructField("known_ransomware_campaign_use", StringType()),
        StructField("kev_required_action", StringType()),
        StructField("kev_due_date", DateType()),
        *_AUDIT,
    ]
)

DIM_VENDOR_PRODUCT_SCHEMA = StructType(
    [
        StructField("vendor_product_key", LongType(), nullable=False),  # xxhash64(vendor||product)
        StructField("vendor", StringType(), nullable=False),
        StructField("product", StringType(), nullable=False),
        StructField("part", StringType()),  # a = application, o = OS, h = hardware
        *_AUDIT,
    ]
)

DIM_CWE_SCHEMA = StructType(
    [
        StructField("cwe_key", IntegerType(), nullable=False),  # 79 for CWE-79; -1 noinfo; -2 Other
        StructField("cwe_id", StringType(), nullable=False),
        StructField(
            "cwe_category", StringType(), nullable=False
        ),  # CWE | NVD-CWE-noinfo | NVD-CWE-Other
        *_AUDIT,
    ]
)

# ---------------------------------------------------------------------------------------------
# Facts
# ---------------------------------------------------------------------------------------------

FACT_CVE_SCHEMA = StructType(
    [
        StructField("cve_id", StringType(), nullable=False),
        StructField("published_date_key", IntegerType(), nullable=False),
        StructField("last_modified_date_key", IntegerType()),
        StructField("kev_added_date_key", IntegerType()),
        StructField("kev_due_date_key", IntegerType()),
        StructField("severity_key", IntegerType(), nullable=False),
        StructField("cvss_v3_score", DoubleType()),
        StructField("is_exploited", IntegerType(), nullable=False),  # 0/1, summable
        StructField("is_ransomware", IntegerType(), nullable=False),  # 0/1
        StructField("days_to_kev", IntegerType()),
        StructField("product_count", IntegerType()),
        StructField("cwe_count", IntegerType()),
        StructField("cve_count", IntegerType(), nullable=False),  # always 1; makes COUNT a SUM
        *_AUDIT,
    ]
)

FACT_CVE_PRODUCT_SCHEMA = StructType(
    [
        StructField("cve_id", StringType(), nullable=False),
        StructField("vendor_product_key", LongType(), nullable=False),
        StructField("published_date_key", IntegerType(), nullable=False),
        StructField("severity_key", IntegerType(), nullable=False),
        StructField("is_exploited", IntegerType(), nullable=False),
        StructField("cvss_v3_score", DoubleType()),
        *_AUDIT,
    ]
)

FACT_CVE_CWE_SCHEMA = StructType(
    [
        StructField("cve_id", StringType(), nullable=False),
        StructField("cwe_key", IntegerType(), nullable=False),
        StructField("published_date_key", IntegerType(), nullable=False),
        StructField("severity_key", IntegerType(), nullable=False),
        StructField("is_exploited", IntegerType(), nullable=False),
        StructField("cvss_v3_score", DoubleType()),
        *_AUDIT,
    ]
)

# ---------------------------------------------------------------------------------------------
# Catalogue of tables: keys, clustering, relationships
# ---------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class GoldTable:
    name: str
    schema: StructType
    primary_key: tuple[str, ...]
    comment: str
    cluster_by: tuple[str, ...] = ()
    kind: str = "dimension"  # dimension | fact


@dataclass(frozen=True)
class ForeignKey:
    table: str
    column: str
    ref_table: str
    ref_column: str
    role: str = ""  # e.g. 'published', 'kev_added' for role-playing dim_date
    active_in_bi: bool = True  # Power BI allows one active relationship per table pair
    extra: dict = field(default_factory=dict)


TABLES: dict[str, GoldTable] = {
    "dim_date": GoldTable(
        "dim_date", DIM_DATE_SCHEMA, ("date_key",), "Calendar dimension, one row per day 1988-2030"
    ),
    "dim_severity": GoldTable(
        "dim_severity",
        DIM_SEVERITY_SCHEMA,
        ("severity_key",),
        "CVSS v3 severity bands (CRITICAL, HIGH, MEDIUM, LOW, NONE, UNKNOWN)",
    ),
    "dim_cve": GoldTable(
        "dim_cve",
        DIM_CVE_SCHEMA,
        ("cve_id",),
        "Descriptive attributes of a CVE plus CISA KEV attributes when listed (SCD type 1)",
    ),
    "dim_vendor_product": GoldTable(
        "dim_vendor_product",
        DIM_VENDOR_PRODUCT_SCHEMA,
        ("vendor_product_key",),
        "Vendor and product parsed from CPE 2.3 criteria (SCD type 1)",
    ),
    "dim_cwe": GoldTable(
        "dim_cwe", DIM_CWE_SCHEMA, ("cwe_key",), "Weakness identifiers seen in NVD (SCD type 1)"
    ),
    "fact_cve": GoldTable(
        "fact_cve",
        FACT_CVE_SCHEMA,
        ("cve_id",),
        "One row per CVE: dates, severity, exploitation flags, days to KEV, counts",
        cluster_by=("published_date_key", "severity_key"),
        kind="fact",
    ),
    "fact_cve_product": GoldTable(
        "fact_cve_product",
        FACT_CVE_PRODUCT_SCHEMA,
        ("cve_id", "vendor_product_key"),
        "Bridge fact: one row per CVE x affected vendor/product",
        cluster_by=("vendor_product_key",),
        kind="fact",
    ),
    "fact_cve_cwe": GoldTable(
        "fact_cve_cwe",
        FACT_CVE_CWE_SCHEMA,
        ("cve_id", "cwe_key"),
        "Bridge fact: one row per CVE x weakness",
        cluster_by=("cwe_key",),
        kind="fact",
    ),
}

FOREIGN_KEYS: list[ForeignKey] = [
    ForeignKey("fact_cve", "cve_id", "dim_cve", "cve_id"),
    ForeignKey("fact_cve", "published_date_key", "dim_date", "date_key", role="published"),
    ForeignKey(
        "fact_cve", "last_modified_date_key", "dim_date", "date_key", "last_modified", False
    ),
    ForeignKey("fact_cve", "kev_added_date_key", "dim_date", "date_key", "kev_added", False),
    ForeignKey("fact_cve", "kev_due_date_key", "dim_date", "date_key", "kev_due", False),
    ForeignKey("fact_cve", "severity_key", "dim_severity", "severity_key"),
    ForeignKey("fact_cve_product", "cve_id", "dim_cve", "cve_id"),
    ForeignKey(
        "fact_cve_product", "vendor_product_key", "dim_vendor_product", "vendor_product_key"
    ),
    ForeignKey("fact_cve_product", "published_date_key", "dim_date", "date_key", role="published"),
    ForeignKey("fact_cve_product", "severity_key", "dim_severity", "severity_key"),
    ForeignKey("fact_cve_cwe", "cve_id", "dim_cve", "cve_id"),
    ForeignKey("fact_cve_cwe", "cwe_key", "dim_cwe", "cwe_key"),
    ForeignKey("fact_cve_cwe", "published_date_key", "dim_date", "date_key", role="published"),
    ForeignKey("fact_cve_cwe", "severity_key", "dim_severity", "severity_key"),
]

WATCHLIST_VIEW = "gold_watchlist_v"

# ---------------------------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------------------------


def column_ddl(schema: StructType) -> str:
    return ", ".join(
        f"{f.name} {f.dataType.simpleString()}{'' if f.nullable else ' NOT NULL'}"
        for f in schema.fields
    )


def create_table_sql(table: GoldTable, gold_schema_fqn: str) -> str:
    """Idempotent CREATE for one Gold table; facts get liquid clustering."""
    cluster = f" CLUSTER BY ({', '.join(table.cluster_by)})" if table.cluster_by else ""
    return (
        f"CREATE TABLE IF NOT EXISTS {gold_schema_fqn}.{table.name} "
        f"({column_ddl(table.schema)}) USING DELTA{cluster} COMMENT '{table.comment}'"
    )


def constraint_sql(gold_schema_fqn: str) -> list[tuple[str, str]]:
    """Informational PK/FK constraints (Unity Catalog does not enforce them, Power BI and
    graders read them). Returns (constraint name, statement) pairs; PKs first."""
    statements: list[tuple[str, str]] = []
    for t in TABLES.values():
        name = f"pk_{t.name}"
        statements.append(
            (
                name,
                f"ALTER TABLE {gold_schema_fqn}.{t.name} ADD CONSTRAINT {name} "
                f"PRIMARY KEY ({', '.join(t.primary_key)})",
            )
        )
    for fk in FOREIGN_KEYS:
        name = f"fk_{fk.table}_{fk.column}"
        statements.append(
            (
                name,
                f"ALTER TABLE {gold_schema_fqn}.{fk.table} ADD CONSTRAINT {name} "
                f"FOREIGN KEY ({fk.column}) REFERENCES {gold_schema_fqn}.{fk.ref_table}({fk.ref_column})",
            )
        )
    return statements


def watchlist_view_sql(gold_schema_fqn: str) -> str:
    """Approved watchlist criteria (ARCHITECTURE 3.4): in KEV, or CVSS >= 9.0 and published in the
    last 90 days. A view so it is never stale."""
    return f"""
        CREATE OR REPLACE VIEW {gold_schema_fqn}.{WATCHLIST_VIEW}
        COMMENT 'Actionable CVEs: exploited (KEV) or critical and published in the last 90 days'
        AS
        SELECT
            f.cve_id,
            d.full_date                       AS published_at,
            s.severity,
            f.cvss_v3_score,
            CAST(f.is_exploited AS BOOLEAN)   AS is_exploited,
            c.kev_vendor_project,
            c.kev_product,
            c.kev_due_date,
            c.kev_required_action,
            c.known_ransomware_campaign_use,
            CASE WHEN f.is_exploited = 1 THEN 'KEV listed' ELSE 'Critical, recent' END AS watch_reason
        FROM {gold_schema_fqn}.fact_cve f
        JOIN {gold_schema_fqn}.dim_date d       ON d.date_key = f.published_date_key
        JOIN {gold_schema_fqn}.dim_severity s   ON s.severity_key = f.severity_key
        JOIN {gold_schema_fqn}.dim_cve c        ON c.cve_id = f.cve_id
        WHERE f.is_exploited = 1
           OR (f.cvss_v3_score >= 9.0 AND d.full_date >= date_sub(current_date(), 90))
    """


def ensure_tables(spark: SparkSession, gold_schema_fqn: str) -> dict[str, str]:
    """Create every Gold table if missing. Returns {short name: fully qualified name}."""
    created = {}
    for t in TABLES.values():
        spark.sql(create_table_sql(t, gold_schema_fqn))
        created[t.name] = f"{gold_schema_fqn}.{t.name}"
    return created


def ensure_constraints(spark: SparkSession, gold_schema_fqn: str) -> dict[str, str]:
    """Add PK/FK constraints; 'exists' when already present, 'skipped: <reason>' on error.
    Never raises: constraints are metadata, not a reason to fail a load."""
    outcome = {}
    for name, sql in constraint_sql(gold_schema_fqn):
        try:
            spark.sql(sql)
            outcome[name] = "added"
        except Exception as exc:  # noqa: BLE001 - informational metadata only
            msg = str(exc)
            outcome[name] = "exists" if "already exists" in msg.lower() else f"skipped: {msg[:90]}"
    return outcome


def ensure_watchlist_view(spark: SparkSession, gold_schema_fqn: str) -> str:
    spark.sql(watchlist_view_sql(gold_schema_fqn))
    return f"{gold_schema_fqn}.{WATCHLIST_VIEW}"
