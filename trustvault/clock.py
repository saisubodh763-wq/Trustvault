"""Single source of time. Tests can move it forward to exercise expiry; nothing
else may call datetime.now() for a security decision."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

_offset = timedelta(0)
FMT = "%Y-%m-%dT%H:%M:%SZ"


def now_dt() -> datetime:
    return datetime.now(timezone.utc) + _offset


def now() -> str:
    return now_dt().strftime(FMT)


def fmt(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime(FMT)


def parse(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def advance(seconds: float) -> None:      # tests only
    global _offset
    _offset += timedelta(seconds=seconds)


def reset() -> None:                      # tests only
    global _offset
    _offset = timedelta(0)
