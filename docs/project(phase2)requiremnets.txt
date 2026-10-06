Context & Objective
With your data source approved and your project structure planned, Phase 2 focuses on hands-on engineering. You will build the foundational layers of your Lakehouse (Bronze and Silver) using Apache Spark.

This phase transitions your project from a basic script to an enterprise-grade data pipeline. You must prioritize software engineering best practices, including explicit contract enforcement, idempotency, fault tolerance, and comprehensive auditing.

Phase 2 Deliverables & Requirements
You must implement the PySpark pipeline in your cloud environment and commit all code to your GitHub repository. Your submission must address the following strict technical requirements:

1. Infrastructure & Environment Setup
Workspace: Initialize your project using either Databricks Community Edition or Microsoft Azure (using your student credits).
Version Control: All PySpark notebooks or scripts must be continuously committed to your GitHub repository.
2. Data Modeling & Schema Enforcement (Bronze & Silver)
Data Dictionary: Provide full, documented data models for both your Bronze and Silver layers, specifying column names, data types, and primary keys.
Strict Schema-on-Read: You must not use Spark's built-in schema inference (e.g., inferSchema=True). You must define your schemas explicitly using PySpark's StructType and StructField APIs before reading the raw files.
Data Types & Casting: Enforce strict data types. Perform necessary casting operations (e.g., converting strings to timestamps, or stringified numbers to doubles) as data moves into the Silver layer.
Metadata Integration: Every record in every table (Bronze and Silver) must include a load_timestamp column indicating exactly when that specific record was ingested or processed.
3. Pipeline Robustness & Idempotency
Idempotent Execution: Your pipeline must be fully idempotent. If the pipeline is executed multiple times on the exact same raw data, the Silver layer (and beyond) must not be impacted (i.e., no duplicate rows). You must demonstrate the use of MERGE INTO (Upsert) patterns to achieve this.
Parameterized Backfills: Your pipeline architecture must not rely on rigid, hardcoded file paths that only process "today's" data. Design your functions/notebooks to accept parameters (e.g., a specific date, batch ID, or folder path) so that backfills from raw files to Bronze, or Bronze to Silver, can be re-executed at will for any historical timeframe.
Schema Drift Handling: Implement logic to handle schema drift. If your source system unexpectedly adds a new column, or changes a data type (e.g., an integer becomes a string), your pipeline should either gracefully evolve the schema (mergeSchema) or quarantine the non-conforming records without crashing the entire batch.
4. Audit & Execution Logging
Dedicated Logging Tables: You must establish a robust logging framework. Create separate operational tables (e.g., pipeline_execution_logs) to record metadata about every pipeline run.
Audit Metrics: Every time a file or table is processed (for both Full and Incremental loads across every layer), your pipeline must write a log entry containing:
    The layer being processed (e.g., Raw-to-Bronze, Bronze-to-Silver).
    The parameter/file processed.
    Execution start and end times.
    Status (Success/Failure).
    Number of rows inserted/updated.
Submission Guidelines for Phase 2

You will submit your updated GitHub repository link. Your repository must contain:
The PySpark notebooks/scripts executing the pipeline.
An updated README.md containing the Bronze and Silver data models.
A brief execution guide explaining how to pass parameters to trigger a backfill versus a standard incremental load.