"""Gold DDL contract: keys exist, FKs point at real PKs, audit columns everywhere, SQL renders."""

from vulnpulse.gold import ddl


def test_every_table_has_audit_columns_and_a_primary_key():
    for t in ddl.TABLES.values():
        names = [f.name for f in t.schema.fields]
        assert names[-2:] == ["batch_id", "load_timestamp"], t.name
        for key in t.primary_key:
            field = t.schema[key]
            assert not field.nullable, f"{t.name}.{key} must be NOT NULL to be a PK"


def test_foreign_keys_reference_existing_primary_keys():
    for fk in ddl.FOREIGN_KEYS:
        assert fk.column in ddl.TABLES[fk.table].schema.fieldNames(), fk
        ref = ddl.TABLES[fk.ref_table]
        assert ref.primary_key == (fk.ref_column,), fk
        # same data type on both sides
        assert (
            ddl.TABLES[fk.table].schema[fk.column].dataType == ref.schema[fk.ref_column].dataType
        ), fk


def test_only_facts_are_clustered_and_dims_are_not():
    for t in ddl.TABLES.values():
        if t.kind == "fact":
            assert t.cluster_by, t.name
            assert set(t.cluster_by) <= set(t.schema.fieldNames())
        else:
            assert not t.cluster_by, t.name


def test_one_active_bi_relationship_per_table_pair():
    """Power BI allows one active relationship between two tables; role-playing dates are inactive."""
    seen = set()
    for fk in ddl.FOREIGN_KEYS:
        if fk.active_in_bi:
            pair = (fk.table, fk.ref_table)
            assert pair not in seen, f"two active relationships for {pair}"
            seen.add(pair)


def test_sql_renders():
    fact = ddl.create_table_sql(ddl.TABLES["fact_cve"], "workspace.vulnpulse_gold")
    assert fact.startswith("CREATE TABLE IF NOT EXISTS workspace.vulnpulse_gold.fact_cve (")
    assert "cve_id string NOT NULL" in fact
    assert "CLUSTER BY (published_date_key, severity_key)" in fact

    dim = ddl.create_table_sql(ddl.TABLES["dim_date"], "workspace.vulnpulse_gold")
    assert "CLUSTER BY" not in dim

    statements = dict(ddl.constraint_sql("workspace.vulnpulse_gold"))
    assert "PRIMARY KEY (cve_id, vendor_product_key)" in statements["pk_fact_cve_product"]
    assert (
        "REFERENCES workspace.vulnpulse_gold.dim_date(date_key)"
        in statements["fk_fact_cve_published_date_key"]
    )

    view = ddl.watchlist_view_sql("workspace.vulnpulse_gold")
    assert "CREATE OR REPLACE VIEW workspace.vulnpulse_gold.gold_watchlist_v" in view
    assert "is_exploited = 1" in view and "cvss_v3_score >= 9.0" in view
