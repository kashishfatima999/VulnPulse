"""Run parameters for the Bronze notebooks.

Everything a run needs arrives through this module, from notebook widgets or job parameters.
No function elsewhere reads widgets or hardcodes a date, path or table name.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

LOAD_TYPES = ("FULL", "INCREMENTAL", "BACKFILL")


def utc_now() -> datetime:
    """Current time in UTC, timezone-aware. The single clock the pipeline uses."""
    return datetime.now(timezone.utc)


def new_batch_id() -> str:
    """A fresh batch identifier. Time-prefixed so it sorts chronologically in the audit table."""
    return f"{utc_now():%Y%m%dT%H%M%SZ}-{uuid.uuid4().hex[:8]}"


def parse_load_type(value: str) -> str:
    normalised = (value or "").strip().upper()
    if normalised not in LOAD_TYPES:
        raise ValueError(f"load_type must be one of {LOAD_TYPES}, got {value!r}")
    return normalised


@dataclass(frozen=True)
class BronzeRunParams:
    """Parameters for one Raw-to-Bronze run.

    load_type    FULL (read files from source_path), INCREMENTAL (API from watermark) or
                 BACKFILL (API for an explicit start_date..end_date window).
    catalog      Unity Catalog catalog, e.g. ``workspace``.
    source_path  File or directory to read for FULL loads. Ignored otherwise.
    start_date / end_date
                 ISO-8601 UTC bounds for BACKFILL. Ignored otherwise.
    batch_id     Caller-supplied id, or a new one when blank.
    """

    load_type: str
    catalog: str = "workspace"
    source_path: str | None = None
    start_date: str | None = None
    end_date: str | None = None
    batch_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "load_type", parse_load_type(self.load_type))
        object.__setattr__(self, "batch_id", self.batch_id.strip() or new_batch_id())
        if self.load_type == "FULL" and not self.source_path:
            raise ValueError("FULL load requires source_path")
        if self.load_type == "BACKFILL" and not (self.start_date and self.end_date):
            raise ValueError("BACKFILL requires start_date and end_date")

    @property
    def bronze_schema(self) -> str:
        return f"{self.catalog}.vulnpulse_bronze"

    @property
    def gold_schema(self) -> str:
        return f"{self.catalog}.vulnpulse_gold"

    def as_dict(self) -> dict:
        return {
            "load_type": self.load_type,
            "catalog": self.catalog,
            "source_path": self.source_path,
            "start_date": self.start_date,
            "end_date": self.end_date,
            "batch_id": self.batch_id,
        }
