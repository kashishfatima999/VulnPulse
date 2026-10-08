"""Parameter parsing (pure Python) and execution-log row construction (Spark)."""

from datetime import datetime, timezone

import pytest

from vulnpulse.audit.execution_log import (
    EXECUTION_LOG_SCHEMA,
    LAYER_RAW_TO_BRONZE,
    STATUS_SUCCESS,
    build_log_row,
)
from vulnpulse.utils.params import BronzeRunParams, new_batch_id, parse_load_type


def test_parse_load_type_normalises_and_rejects():
    assert parse_load_type(" full ") == "FULL"
    assert parse_load_type("incremental") == "INCREMENTAL"
    with pytest.raises(ValueError):
        parse_load_type("DAILY")


@pytest.mark.parametrize("load_type", ["FULL", "INCREMENTAL", "BACKFILL"])
def test_every_load_type_requires_source_path(load_type):
    with pytest.raises(ValueError):
        BronzeRunParams(load_type=load_type)
    p = BronzeRunParams(load_type=load_type, source_path="/Volumes/x/y/z")
    assert p.batch_id  # auto-generated
    assert p.bronze_schema == "workspace.vulnpulse_bronze"


def test_dates_must_come_in_pairs():
    with pytest.raises(ValueError):
        BronzeRunParams(load_type="BACKFILL", source_path="/v", start_date="2026-01-01T00:00:00")
    p = BronzeRunParams(
        load_type="BACKFILL",
        source_path="/v",
        start_date="2026-01-01T00:00:00",
        end_date="2026-01-02T00:00:00",
        batch_id="  given  ",
    )
    assert p.batch_id == "given"


def test_batch_ids_are_unique_and_sortable():
    a, b = new_batch_id(), new_batch_id()
    assert a != b
    assert a[:8].isdigit()


@pytest.mark.spark
def test_build_log_row_matches_schema(spark):
    started = datetime(2026, 10, 8, 10, 0, tzinfo=timezone.utc)
    finished = datetime(2026, 10, 8, 10, 0, 42, tzinfo=timezone.utc)
    df = build_log_row(
        spark,
        batch_id="b1",
        layer=LAYER_RAW_TO_BRONZE,
        source="file.json",
        load_type="FULL",
        parameters={"load_type": "FULL", "source_path": "file.json"},
        started_at=started,
        finished_at=finished,
        status=STATUS_SUCCESS,
        rows_read=10,
        rows_inserted=10,
        rows_updated=0,
    )
    assert df.schema == EXECUTION_LOG_SCHEMA
    row = df.first()
    assert row["status"] == "SUCCESS"
    assert row["finished_at"] - row["started_at"] == finished - started
    assert '"source_path": "file.json"' in row["parameters"]
    assert row["load_timestamp"] == finished.replace(tzinfo=None)


@pytest.mark.spark
def test_build_log_row_rejects_bad_status(spark):
    now = datetime.now(timezone.utc)
    with pytest.raises(ValueError):
        build_log_row(
            spark,
            batch_id="b",
            layer=LAYER_RAW_TO_BRONZE,
            source="s",
            load_type="FULL",
            parameters=None,
            started_at=now,
            finished_at=now,
            status="OK",
        )
