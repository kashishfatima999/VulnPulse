"""Gold layer: star schema (dimensions + facts) built from Silver, refreshed with MERGE.

Modules
    ddl          every Gold table's StructType, keys, clustering, informational PK/FK constraints
    keys         deterministic key expressions shared by all builders (date, severity, vendor, CWE)
    dims_static  dim_date and dim_severity (generated, overwritten idempotently)
    cve          dim_cve and fact_cve                         (Kashish)
    products     dim_vendor_product and fact_cve_product     (Zahra)
    cwe          dim_cwe and fact_cve_cwe                     (Zahra)
    run          Gold watermark, incremental/full modes, orchestration used by 04_gold
"""
