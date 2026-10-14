"""Postgres connection pool + timestamp helpers for the ingest API and
the dashboard SQL loaders.

Single source of truth for `PG_DSN` parsing, pool sizing, and timestamp
parity. Loopback Postgres on the storage server: pool exists to avoid
per-request connect overhead, not to mask network jitter.

Timestamp policy
================
All schema timestamps are `timestamptz` and stored in UTC. Wherever the
dashboard formats from a literal manifest string today, a sibling raw-string
column (`*_str`) is preserved so display output is byte-identical.

`to_ts()` accepts:
    - `float`: epoch seconds (UTC) — used for time.time() values.
    - "%Y%m%d-%H%M%S" / "%Y-%m-%dT%H:%M:%S" — interpreted in AGENT_TIMEZONE
      (default UTC; warns once if unset and a legacy string is encountered).
    - ISO-8601 with offset: parsed as-is.

UPSERT patterns
===============
- Full event (POST .../turns, .../tests, ...): use
      INSERT … ON CONFLICT (pk) DO UPDATE SET col = EXCLUDED.col
  for each column in the request payload. Workers send a complete record.

- Partial PATCH (PATCH /ingest/runs/{run_id}, PATCH /ingest/sweeps/{sweep_id}):
  build the SET clause dynamically from keys present in the JSON body. Do
  NOT use COALESCE(EXCLUDED.col, table.col) — it would prevent legitimately
  setting a column to NULL.
"""

from __future__ import annotations

import datetime as _dt
import logging
import os
import re
from typing import Any

import psycopg
from psycopg_pool import ConnectionPool

logger = logging.getLogger(__name__)


_LEGACY_FMTS = ("%Y%m%d-%H%M%S", "%Y-%m-%dT%H:%M:%S")
_ISO_WITH_OFFSET_RE = re.compile(r".*[+\-]\d{2}:?\d{2}$|.*Z$")

_TZ_HINT_WARNED = False


def _agent_tz() -> _dt.tzinfo:
    """Resolve AGENT_TIMEZONE to a tzinfo. Default UTC."""
    name = os.environ.get("AGENT_TIMEZONE", "").strip()
    if not name or name.upper() == "UTC":
        return _dt.timezone.utc
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(name)
    except Exception as e:
        logger.warning(
            "AGENT_TIMEZONE=%r is not a valid zone name (%s); falling back to UTC",
            name,
            e,
        )
        return _dt.timezone.utc


def to_ts(value: Any, *, tz_hint: str | None = None) -> _dt.datetime | None:
    """Coerce a value from an ingest payload into a UTC `datetime`.

    `value` may be:
        - None / "" → returns None
        - int / float → epoch seconds (UTC)
        - str matching ISO-8601 with offset → parsed as-is
        - str matching %Y%m%d-%H%M%S or %Y-%m-%dT%H:%M:%S → interpreted in
          AGENT_TIMEZONE (or `tz_hint` if given).
    """
    global _TZ_HINT_WARNED
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return _dt.datetime.fromtimestamp(float(value), tz=_dt.timezone.utc)
    if isinstance(value, _dt.datetime):
        if value.tzinfo is None:
            return value.replace(tzinfo=_dt.timezone.utc)
        return value.astimezone(_dt.timezone.utc)
    if not isinstance(value, str):
        raise TypeError(f"to_ts: unsupported type {type(value).__name__}")

    s = value.strip()
    if _ISO_WITH_OFFSET_RE.match(s):
        try:
            dt = _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
            return dt.astimezone(_dt.timezone.utc)
        except ValueError:
            pass

    tz = _dt.timezone.utc
    if tz_hint:
        try:
            from zoneinfo import ZoneInfo

            tz = ZoneInfo(tz_hint)
        except Exception:
            tz = _agent_tz()
    else:
        env_tz = os.environ.get("AGENT_TIMEZONE", "").strip()
        if not env_tz and not _TZ_HINT_WARNED:
            logger.warning(
                "AGENT_TIMEZONE not set; legacy timestamp %r will be parsed as UTC", s
            )
            _TZ_HINT_WARNED = True
        tz = _agent_tz()

    for fmt in _LEGACY_FMTS:
        try:
            naive = _dt.datetime.strptime(s, fmt)
        except ValueError:
            continue
        return naive.replace(tzinfo=tz).astimezone(_dt.timezone.utc)

    raise ValueError(f"to_ts: unrecognized timestamp format: {s!r}")


# ─── Connection pool ───────────────────────────────────────────────────────

_POOL: ConnectionPool | None = None


def get_pool() -> ConnectionPool:
    """Lazy-init a process-wide pool. Localhost Postgres → small pool."""
    global _POOL
    if _POOL is None:
        dsn = os.environ.get("PG_DSN")
        if not dsn:
            raise RuntimeError(
                "PG_DSN is not set. The ingest API and SQL-backed dashboard both "
                "require a Postgres DSN — set it in ~/.agentic-fuzz-master.env."
            )
        _POOL = ConnectionPool(
            conninfo=dsn,
            min_size=2,
            max_size=10,
            timeout=5.0,
            open=True,
            kwargs={"row_factory": psycopg.rows.dict_row},
        )
    return _POOL


def close_pool() -> None:
    """For graceful shutdown / test teardown."""
    global _POOL
    if _POOL is not None:
        _POOL.close()
        _POOL = None


def healthcheck() -> bool:
    """Return True iff `SELECT 1` succeeds."""
    try:
        with get_pool().connection() as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
                cur.fetchone()
        return True
    except Exception as e:
        logger.warning("DB healthcheck failed: %s", e)
        return False


# ─── Helpers ────────────────────────────────────────────────────────────────


def build_partial_update(
    table: str,
    pk_cols: list[str],
    pk_values: list[Any],
    fields: dict[str, Any],
) -> tuple[str, list[Any]]:
    """Build a parameterized partial-UPDATE statement from the keys present
    in `fields` (drops the PK columns from the update set). Returns
    `(sql, params)` ready for cursor.execute().

    Caller is responsible for building/handling the INSERT half if the row
    may not yet exist — this helper is for the PATCH endpoints, where the
    row is expected to exist (created by an earlier POST or a stub).
    """
    update_cols = [c for c in fields.keys() if c not in pk_cols]
    if not update_cols:
        # No-op: still emit a valid statement that touches no rows.
        return f"SELECT 1 FROM {table} WHERE FALSE", []
    set_clause = ", ".join(f"{c} = %s" for c in update_cols)
    where_clause = " AND ".join(f"{c} = %s" for c in pk_cols)
    params = [fields[c] for c in update_cols] + list(pk_values)
    sql = f"UPDATE {table} SET {set_clause} WHERE {where_clause}"
    return sql, params
