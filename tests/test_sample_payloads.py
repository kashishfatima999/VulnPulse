"""Tests against the Phase 1 sample payloads in data/.

These are deliberately small. They prove two things for CI:
  * the committed samples have the shape the Bronze layer will assume, and
  * a local PySpark session can read them with an explicit schema (no inferSchema).
"""

import json
import re

import pytest

CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

NVD_SAMPLES = ["nvd_full_load_sample.json", "nvd_incremental_load_sample.json"]


def _load(data_dir, filename):
    with open(data_dir / filename, encoding="utf-8") as fp:
        return json.load(fp)


@pytest.mark.parametrize("filename", NVD_SAMPLES)
def test_nvd_sample_has_expected_shape(data_dir, filename):
    payload = _load(data_dir, filename)

    assert payload["format"] == "NVD_CVE"
    assert payload["version"] == "2.0"
    assert payload["resultsPerPage"] == len(payload["vulnerabilities"])

    for item in payload["vulnerabilities"]:
        cve = item["cve"]
        assert CVE_ID_PATTERN.match(cve["id"]), cve["id"]
        assert cve["published"]
        assert cve["lastModified"]
        assert cve["vulnStatus"]


def test_kev_sample_has_expected_shape(data_dir):
    payload = _load(data_dir, "cisa_kev_sample.json")

    assert payload["catalogVersion"]
    assert payload["count"] == len(payload["vulnerabilities"])

    for item in payload["vulnerabilities"]:
        assert CVE_ID_PATTERN.match(item["cveID"]), item["cveID"]
        assert item["vendorProject"]
        assert item["product"]
        assert item["dateAdded"]


def test_manifest_counts_match_files(data_dir):
    manifest = _load(data_dir, "source_manifest.json")

    for name, meta in manifest["artifacts"].items():
        payload = _load(data_dir, meta["file"])
        assert len(payload["vulnerabilities"]) == meta["record_count"], name


@pytest.mark.spark
def test_nvd_sample_reads_with_explicit_schema(spark, data_dir):
    """Reading with an explicit StructType is the project contract: never inferSchema."""
    from pyspark.sql.types import ArrayType, IntegerType, StringType, StructField, StructType

    cve_schema = StructType(
        [
            StructField("id", StringType(), nullable=False),
            StructField("sourceIdentifier", StringType()),
            StructField("published", StringType()),
            StructField("lastModified", StringType()),
            StructField("vulnStatus", StringType()),
        ]
    )
    page_schema = StructType(
        [
            StructField("resultsPerPage", IntegerType()),
            StructField("startIndex", IntegerType()),
            StructField("totalResults", IntegerType()),
            StructField("format", StringType()),
            StructField("version", StringType()),
            StructField("timestamp", StringType()),
            StructField(
                "vulnerabilities",
                ArrayType(StructType([StructField("cve", cve_schema)])),
            ),
        ]
    )

    path = str(data_dir / "nvd_full_load_sample.json")
    df = spark.read.schema(page_schema).option("multiLine", True).json(path)

    assert df.count() == 1  # one API page per file
    cves = df.selectExpr("explode(vulnerabilities.cve) AS cve").select("cve.*")
    assert cves.count() == 10
    assert cves.filter("id IS NULL").count() == 0
