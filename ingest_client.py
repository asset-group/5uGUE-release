"""Worker-side outbox enqueuer.

Hooks call `enqueue(kind, payload, run_id=..., session_id=..., sweep_id=...)`
to append a single line to `~/.agent-fuzz-outbox.jsonl`. The HTTP POST is
deferred to `scripts/outbox_flush.py` running as a `systemctl --user`
service or cron `@reboot`, so the agent's hot path stays disk-only.

The envelope below is the source of truth — every ingest event in the
pipeline (live worker, backfill, e2e tests) constructs one of these. Server
endpoints rely on it for FK stub creation, so identity fields (host_id,
run_id|sweep_id, session_id) MUST live on the envelope, not just the
payload. See `ingest.py` for the matching server-side handlers.

Envelope schema:

    {
      "kind":        str,                # event type tag
      "host_id":     str,                # always present (constants.HOST_ID)
      "run_id":      str | None,         # for run-scoped events
      "sweep_id":    str | None,         # for sweep-scoped events
      "session_id":  str | None,         # for session findings, tests
      "enqueued_at": float,              # time.time() UTC epoch
      "payload":     dict,               # kind-specific record
    }
"""

from __future__ import annotations

import contextlib
import fcntl
import json
import logging
import os
import time
from typing import Any, Optional

logger = logging.getLogger(__name__)

OUTBOX_PATH = os.environ.get(
    "AGENT_OUTBOX_PATH",
    os.path.expanduser("~/.agent-fuzz-outbox.jsonl"),
)
# Must match scripts/outbox_flush.py:LOCK_SUFFIX so the flusher's
# rotation flock and these appenders serialize against one another.
LOCK_SUFFIX = ".lock"


@contextlib.contextmanager
def _outbox_lock(path: str):
    """Same lock the flusher takes during atomic OUTBOX→INFLIGHT rotation."""
    lock_path = path + LOCK_SUFFIX
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


# Whitelist enforced both client- and server-side. Any new event type must
# be registered here AND given a handler in dashboard/ingest.py.
KINDS = frozenset(
    {
        "run_start",
        "run_finish",
        "turn",
        "resource",
        "test",
        "finding",  # session finding
        "global_finding",
        "strategy",
        "sweep_start",
        "sweep_finish",
        "sweep_test",
        "sweep_progress",
        "evaluation",
        "blob",
    }
)


def _host_id() -> str:
    """Resolve HOST_ID at call time so tests can monkeypatch the env var."""
    try:
        from constants import HOST_ID

        return HOST_ID
    except Exception:
        import socket

        return os.environ.get("AGENT_HOST_ID") or socket.gethostname()


def _disabled() -> bool:
    """If AGENT_NO_INGEST=1, hooks are no-ops. Master/dev/CI uses this."""
    return os.environ.get("AGENT_NO_INGEST") == "1"


_ACTIVE_PROTOCOL: Optional[str] = None
_ACTIVE_DEVICE: Optional[str] = None


def set_active_session_context(protocol: str, device: str) -> None:
    """Set the active fuzzing context for enqueuer checks."""
    global _ACTIVE_PROTOCOL, _ACTIVE_DEVICE
    _ACTIVE_PROTOCOL = protocol
    _ACTIVE_DEVICE = device


def enqueue(
    kind: str,
    payload: dict[str, Any],
    *,
    run_id: Optional[str] = None,
    sweep_id: Optional[str] = None,
    session_id: Optional[str] = None,
    host_id: Optional[str] = None,
) -> None:
    """Append a single envelope line to the outbox.

    Failures are logged and swallowed — the agent must never crash because
    the outbox file is unwritable. The flusher daemon is the durability
    boundary; if a write fails here, that one event is lost, not the run.
    """
    if _disabled():
        return
    if kind not in KINDS:
        logger.warning("ingest_client.enqueue: unknown kind %r — dropped", kind)
        return

    global _ACTIVE_PROTOCOL, _ACTIVE_DEVICE
    active_proto = _ACTIVE_PROTOCOL or os.environ.get("ACTIVE_FUZZ_PROTOCOL")
    active_dev = _ACTIVE_DEVICE or os.environ.get("ACTIVE_FUZZ_DEVICE")
    
    # Preflight check
    if active_proto is not None:
        if "protocol" in payload and payload["protocol"] != active_proto:
            raise ValueError(
                f"Validation Error: Ingest payload protocol '{payload['protocol']}' "
                f"does not match active context protocol '{active_proto}'."
            )
    if active_dev is not None:
        if "device" in payload and payload["device"] != active_dev:
            raise ValueError(
                f"Validation Error: Ingest payload device '{payload['device']}' "
                f"does not match active context device '{active_dev}'."
            )

    envelope = {
        "kind": kind,
        "host_id": host_id or _host_id(),
        "run_id": run_id,
        "sweep_id": sweep_id,
        "session_id": session_id,
        "enqueued_at": time.time(),
        "payload": payload,
    }
    line = json.dumps(envelope, separators=(",", ":")) + "\n"
    try:
        # Take the same exclusive flock the flusher uses for OUTBOX→INFLIGHT
        # rotation. Without this, an append could land mid-rotation and be
        # silently lost (write to OUTBOX after rename, before fresh OUTBOX
        # is recreated, or vice versa).
        with _outbox_lock(OUTBOX_PATH):
            with open(OUTBOX_PATH, "a") as f:
                f.write(line)
    except Exception as e:
        logger.warning(
            "ingest_client.enqueue: write failed (%s) — event dropped: kind=%s", e, kind
        )
