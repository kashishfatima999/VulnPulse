"""Explicit schemas for the CISA Known Exploited Vulnerabilities (KEV) catalog JSON feed.

Same two-level idea as :mod:`vulnpulse.schemas.nvd`: Bronze reads the catalog envelope typed and
keeps each vulnerability entry as a verbatim JSON string; Silver parses that string with the
typed record schema.
"""

from pyspark.sql.types import ArrayType, IntegerType, StringType, StructField, StructType

KEV_CATALOG_RAW_SCHEMA = StructType(
    [
        StructField("title", StringType()),
        StructField("catalogVersion", StringType()),
        StructField("dateReleased", StringType()),
        StructField("count", IntegerType()),
        # Each entry captured verbatim as a JSON string (see nvd.py for why this works).
        StructField("vulnerabilities", ArrayType(StringType())),
    ]
)

KEV_RECORD_SCHEMA = StructType(
    [
        StructField("cveID", StringType(), nullable=False),
        StructField("vendorProject", StringType()),
        StructField("product", StringType()),
        StructField("vulnerabilityName", StringType()),
        StructField("dateAdded", StringType()),
        StructField("shortDescription", StringType()),
        StructField("requiredAction", StringType()),
        StructField("dueDate", StringType()),
        StructField("knownRansomwareCampaignUse", StringType()),
        StructField("notes", StringType()),
        StructField("cwes", ArrayType(StringType())),
        # Added by CISA in 2026 alongside BOD 26-04; absent from older catalog snapshots.
        StructField("forensicTriage", StringType()),
    ]
)

KEV_KNOWN_KEYS = frozenset(f.name for f in KEV_RECORD_SCHEMA.fields)
