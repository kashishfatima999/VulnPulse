"""Explicit schemas for NIST NVD CVE API 2.0 payloads and yearly feeds.

Two schemas, two jobs:

* ``NVD_PAGE_RAW_SCHEMA`` is what Bronze reads files with. The page envelope is typed, but each
  CVE object is captured as a **verbatim JSON string**. Spark's JSON reader does this when a
  field declared as ``StringType`` meets an object: it copies the whole object as text. That gives
  us raw preservation (unknown or newly added source fields are kept, not dropped) while still
  satisfying the rule that every read uses an explicit ``StructType``.

* ``NVD_CVE_SCHEMA`` is the typed contract for one CVE object. Silver applies it with
  ``from_json(raw_json, NVD_CVE_SCHEMA)``. Fields present in the source but absent here are
  schema drift candidates and should be detected and logged, not silently lost.

Dates stay ``StringType`` here on purpose. NVD emits ``2026-09-24T15:38:04.713`` with no zone.
Casting to ``TimestampType`` (UTC) is a Silver responsibility.
"""

from pyspark.sql.types import (
    ArrayType,
    BooleanType,
    DoubleType,
    IntegerType,
    StringType,
    StructField,
    StructType,
)

# ---------------------------------------------------------------------------------------------
# Bronze read schema: typed envelope, raw CVE strings
# ---------------------------------------------------------------------------------------------

NVD_PAGE_RAW_SCHEMA = StructType(
    [
        StructField("resultsPerPage", IntegerType()),
        StructField("startIndex", IntegerType()),
        StructField("totalResults", IntegerType()),
        StructField("format", StringType()),
        StructField("version", StringType()),
        StructField("timestamp", StringType()),
        StructField(
            "vulnerabilities",
            ArrayType(StructType([StructField("cve", StringType())])),
        ),
    ]
)

# ---------------------------------------------------------------------------------------------
# Typed CVE contract (used by Silver via from_json)
# ---------------------------------------------------------------------------------------------

_LANG_VALUE = StructType(
    [
        StructField("lang", StringType()),
        StructField("value", StringType()),
    ]
)

_CVE_TAG = StructType(
    [
        StructField("sourceIdentifier", StringType()),
        StructField("tags", ArrayType(StringType())),
    ]
)

_CVSS_DATA_V3 = StructType(
    [
        StructField("version", StringType()),
        StructField("vectorString", StringType()),
        StructField("baseScore", DoubleType()),
        StructField("baseSeverity", StringType()),
        StructField("attackVector", StringType()),
        StructField("attackComplexity", StringType()),
        StructField("privilegesRequired", StringType()),
        StructField("userInteraction", StringType()),
        StructField("scope", StringType()),
        StructField("confidentialityImpact", StringType()),
        StructField("integrityImpact", StringType()),
        StructField("availabilityImpact", StringType()),
    ]
)

_CVSS_METRIC_V3 = StructType(
    [
        StructField("source", StringType()),
        StructField("type", StringType()),
        StructField("cvssData", _CVSS_DATA_V3),
        StructField("exploitabilityScore", DoubleType()),
        StructField("impactScore", DoubleType()),
    ]
)

_CVSS_DATA_V2 = StructType(
    [
        StructField("version", StringType()),
        StructField("vectorString", StringType()),
        StructField("baseScore", DoubleType()),
        StructField("accessVector", StringType()),
        StructField("accessComplexity", StringType()),
        StructField("authentication", StringType()),
        StructField("confidentialityImpact", StringType()),
        StructField("integrityImpact", StringType()),
        StructField("availabilityImpact", StringType()),
    ]
)

_CVSS_METRIC_V2 = StructType(
    [
        StructField("source", StringType()),
        StructField("type", StringType()),
        StructField("cvssData", _CVSS_DATA_V2),
        StructField("baseSeverity", StringType()),
        StructField("exploitabilityScore", DoubleType()),
        StructField("impactScore", DoubleType()),
    ]
)

_METRICS = StructType(
    [
        StructField("cvssMetricV31", ArrayType(_CVSS_METRIC_V3)),
        StructField("cvssMetricV30", ArrayType(_CVSS_METRIC_V3)),
        StructField("cvssMetricV2", ArrayType(_CVSS_METRIC_V2)),
    ]
)

_WEAKNESS = StructType(
    [
        StructField("source", StringType()),
        StructField("type", StringType()),
        StructField("description", ArrayType(_LANG_VALUE)),
    ]
)

_CPE_MATCH = StructType(
    [
        StructField("vulnerable", BooleanType()),
        StructField("criteria", StringType()),
        StructField("matchCriteriaId", StringType()),
        StructField("versionStartIncluding", StringType()),
        StructField("versionStartExcluding", StringType()),
        StructField("versionEndIncluding", StringType()),
        StructField("versionEndExcluding", StringType()),
    ]
)

_NODE = StructType(
    [
        StructField("operator", StringType()),
        StructField("negate", BooleanType()),
        StructField("cpeMatch", ArrayType(_CPE_MATCH)),
    ]
)

_CONFIGURATION = StructType(
    [
        StructField("operator", StringType()),
        StructField("negate", BooleanType()),
        StructField("nodes", ArrayType(_NODE)),
    ]
)

_REFERENCE = StructType(
    [
        StructField("url", StringType()),
        StructField("source", StringType()),
        StructField("tags", ArrayType(StringType())),
    ]
)

NVD_CVE_SCHEMA = StructType(
    [
        StructField("id", StringType(), nullable=False),
        StructField("sourceIdentifier", StringType()),
        StructField("published", StringType()),
        StructField("lastModified", StringType()),
        StructField("vulnStatus", StringType()),
        StructField("cveTags", ArrayType(_CVE_TAG)),
        StructField("descriptions", ArrayType(_LANG_VALUE)),
        StructField("metrics", _METRICS),
        StructField("weaknesses", ArrayType(_WEAKNESS)),
        StructField("configurations", ArrayType(_CONFIGURATION)),
        StructField("references", ArrayType(_REFERENCE)),
        # Present only on CVEs that are in the CISA KEV catalog.
        StructField("cisaExploitAdd", StringType()),
        StructField("cisaActionDue", StringType()),
        StructField("cisaRequiredAction", StringType()),
        StructField("cisaVulnerabilityName", StringType()),
    ]
)

# Top-level keys we know about. Anything else in a raw record is schema drift.
NVD_CVE_KNOWN_KEYS = frozenset(f.name for f in NVD_CVE_SCHEMA.fields) | {
    # Known but intentionally not modelled (not needed for analytics):
    "affected",
    "evaluatorComment",
    "evaluatorSolution",
    "evaluatorImpact",
}
