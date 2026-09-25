# VulnPulse: Security, PII Governance & FinOps Strategy

## 1. Personally Identifiable Information (PII) Analysis & Governance

### 1.1 Source Assessment
The data ingested by VulnPulse consists of public vulnerability intelligence (CVE records from NIST NVD and exploited catalogues from CISA). As a baseline, this domain does **not** process end-user personal credentials, financial transaction logs, customer profiles, or private IP address spaces.

### 1.2 Identified Sensitive Pattern: `sourceIdentifier`
In NVD CVE 2.0 payloads, the `sourceIdentifier` attribute records the submitting organization or individual researcher. In certain historical entries, this field is populated with a direct contact email address (e.g., `security-alert@...` or researcher personal emails).

### 1.3 Handling Strategy
1. **Detection:** Regex pattern matching for email signatures (`[\w\.-]+@[\w\.-]+\.\w+`) in incoming Bronze records.
2. **Transformation Policy:**
   - The raw string is suppressed from analytical `silver_cve` and downstream Gold tables.
   - A sanitized boolean column `has_source_identifier: Boolean` is derived for provenance accounting without leaking personal contact info.
3. **Reference URLs:** Reference links submitted by researchers are retained for provenance and CVE validation, but web crawling of arbitrary external links is restricted to avoid untrusted external content.
4. **Credential Isolation:** API keys (such as `NVD_API_KEY`) are accessed strictly through environment variables or Databricks Secret Scopes—never hardcoded or committed to git.

---

## 2. FinOps & Resource Optimization (Free Tier Guardrails)

VulnPulse is designed to operate within the quotas of **Databricks Free Edition / Azure for Students**.

### 2.1 Storage & Compute Guardrails
| Guardrail | Strategy | Impact |
|---|---|---|
| **No Big Data in Git** | The repository only versions sample excerpts (<100 KB). Full yearly archives (~132 MiB) are excluded via `.gitignore`. | Prevents git bloat and repository quota violations. |
| **Watermarked Incrementals** | Incremental runs fetch only records modified since the last watermark timestamp rather than reprocessing all historical baseline data. | Reduces compute cluster run time by >90% per batch. |
| **Lakehouse Pruning** | Temporary landing JSON files are deleted once committed to Delta format. | Keeps persistent storage footprint well below the 2.0 GB target limit. |
| **Selective Projection** | Silver & Gold layers filter out unused nested metadata (e.g. raw multi-language translation objects). | Minimizes memory footprint and prevents driver out-of-memory errors on serverless clusters. |
| **Progressive Testing** | Development ladder: tests run on 10-record samples, then single-year partitions, before multi-year runs. | Avoids accidental cluster credit burn during debugging. |
