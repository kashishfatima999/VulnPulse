"""Landing-folder manifest and window resolution.

Databricks Free Edition serverless compute has no outbound internet (only PyPI resolves), so
source acquisition runs outside Databricks: ``scripts/fetch_nvd.py`` and ``scripts/fetch_kev.py``
download into a local landing folder and write ``manifest.json`` next to the files. The folder is
uploaded to the Unity Catalog volume and the Bronze notebook reads the manifest to learn the
window, the source URL and the load type. This keeps the notebook free of network calls and keeps
every run parameterised by data, not by code.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

MANIFEST_NAME = "manifest.json"


def resolve_window(
    start: str | None,
    end: str | None,
    hours: float | None,
    now: datetime,
) -> tuple[str, datetime, datetime]:
    """Turn CLI inputs into ``(load_type, start, end)``.

    * ``end`` given            -> BACKFILL over ``[start, end)``; ``start`` is required.
    * no ``end``, ``start`` given -> INCREMENTAL from ``start`` (the last watermark) to now.
    * neither                  -> INCREMENTAL over the last ``hours`` (default 24).
    """
    end_dt = parse_utc(end) if end else now
    if end:
        if not start:
            raise ValueError("--end requires --start (a backfill needs both bounds)")
        start_dt = parse_utc(start)
        load_type = "BACKFILL"
    elif start:
        start_dt = parse_utc(start)
        load_type = "INCREMENTAL"
    else:
        start_dt = now - timedelta(hours=hours if hours is not None else 24)
        load_type = "INCREMENTAL"
    if start_dt >= end_dt:
        raise ValueError(f"empty window: start={start_dt.isoformat()} end={end_dt.isoformat()}")
    return load_type, start_dt, end_dt


def parse_utc(value: str) -> datetime:
    """``2026-10-01``, ``2026-10-01T00:00:00``, ``...Z`` or with offset -> aware UTC datetime."""
    ts = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    return ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts.astimezone(timezone.utc)


def write_manifest(out_dir: str, **fields) -> str:
    """Write ``manifest.json`` into ``out_dir``; datetimes are stored as ISO-8601 UTC strings."""
    payload = {
        k: (v.astimezone(timezone.utc).isoformat() if isinstance(v, datetime) else v)
        for k, v in fields.items()
    }
    path = Path(out_dir) / MANIFEST_NAME
    path.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    return str(path)


def read_manifest(folder: str) -> dict | None:
    """Read ``manifest.json`` from a local or ``/Volumes/...`` folder. ``None`` when absent."""
    path = Path(folder.replace("file:", "", 1)) / MANIFEST_NAME
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))
