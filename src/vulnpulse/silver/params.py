"""Run parameters for the Bronze-to-Silver notebook.

Blank filters process every Bronze row (the normal run; MERGE makes that safe and idempotent).
``batch_id`` or a ``from_date``/``to_date`` window re-processes a slice of history (a backfill).
"""

from __future__ import annotations

from dataclasses import dataclass

from pyspark.sql import DataFrame
from pyspark.sql import functions as F

from vulnpulse.utils.params import new_batch_id


@dataclass(frozen=True)
class SilverRunParams:
    catalog: str = "workspace"
    batch_id: str | None = None  # Bronze batch to (re)process; None = all
    from_date: str | None = None  # inclusive, YYYY-MM-DD, on Bronze load_timestamp (UTC)
    to_date: str | None = None  # inclusive, YYYY-MM-DD
    run_id: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "run_id", self.run_id.strip() or new_batch_id())

    @property
    def bronze_schema(self) -> str:
        return f"{self.catalog}.vulnpulse_bronze"

    @property
    def silver_schema(self) -> str:
        return f"{self.catalog}.vulnpulse_silver"

    @property
    def gold_schema(self) -> str:
        return f"{self.catalog}.vulnpulse_gold"

    @property
    def load_type(self) -> str:
        """How the audit row labels this run: a filtered run is a backfill of that slice."""
        return "BACKFILL" if (self.batch_id or self.from_date or self.to_date) else "FULL"

    def as_dict(self) -> dict:
        return {
            "catalog": self.catalog,
            "batch_id": self.batch_id,
            "from_date": self.from_date,
            "to_date": self.to_date,
            "run_id": self.run_id,
        }


def filter_bronze(bronze: DataFrame, params: SilverRunParams) -> DataFrame:
    df = bronze
    if params.batch_id:
        df = df.where(F.col("batch_id") == params.batch_id)
    if params.from_date:
        df = df.where(F.to_date("load_timestamp") >= F.lit(params.from_date).cast("date"))
    if params.to_date:
        df = df.where(F.to_date("load_timestamp") <= F.lit(params.to_date).cast("date"))
    return df