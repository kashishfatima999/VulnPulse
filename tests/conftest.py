"""Shared pytest fixtures for VulnPulse."""

import os
import sys
from pathlib import Path

import pytest

# Spark launches Python workers with the "python3" command. On Windows that can resolve to the
# Microsoft Store stub and the worker never connects back. Pin it to the interpreter running pytest.
os.environ.setdefault("PYSPARK_PYTHON", sys.executable)
os.environ.setdefault("PYSPARK_DRIVER_PYTHON", sys.executable)

REPO_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = REPO_ROOT / "data"


@pytest.fixture(scope="session")
def data_dir() -> Path:
    return DATA_DIR


@pytest.fixture(scope="session")
def spark():
    """A small local SparkSession shared by all tests in the run.

    Imported lazily so tests that never touch Spark do not pay for the JVM start-up.
    """
    from pyspark.sql import SparkSession

    session = (
        SparkSession.builder.master("local[2]")
        .appName("vulnpulse-tests")
        .config("spark.sql.shuffle.partitions", "2")
        .config("spark.ui.enabled", "false")
        .config("spark.sql.session.timeZone", "UTC")
        .getOrCreate()
    )
    yield session
    session.stop()
