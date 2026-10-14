#!/usr/bin/env python3
"""Worker outbox flusher.

Loop:
  1. flock(OUTBOX); rename OUTBOX → INFLIGHT (atomic). New writes go to a
     fresh OUTBOX. The flock window is microseconds.
  2. Group lines by (kind, run_id|sweep_id), batch ≤500, POST.
  3. 2xx → drop. 4xx → move event to dead.jsonl (malformed; do not retry
     forever). 5xx / network → sleep+backoff, re-prepend INFLIGHT under flock.

Run as a systemctl --user service or cron @reboot. AGENT_INGEST_URL and
AGENT_INGEST_TOKEN come from ~/.agentic-fuzz-sync.env.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import json
import logging
import os
import sys
import time
from collections import defaultdict
from typing import Any, Iterable

import requests

logger = logging.getLogger("outbox_flush")

ENV_FILE = os.path.expanduser("~/.agentic-fuzz-sync.env")
DEFAULT_OUTBOX = os.path.expanduser("~/.agent-fuzz-outbox.jsonl")
INFLIGHT_SUFFIX = ".inflight"
DEAD_SUFFIX = ".dead.jsonl"
LOCK_SUFFIX = ".lock"

BATCH_SIZE = 500
INITIAL_BACKOFF = 2.0
MAX_BACKOFF = 60.0
HTTP_TIMEOUT = 30.0


# ─── Env ───────────────────────────────────────────────────────────────────


def _load_env() -> dict[str, str]:
    out: dict[str, str] = {}
    if not os.path.exists(ENV_FILE):
        return out
    with open(ENV_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


# ─── Lock + atomic rotation ────────────────────────────────────────────────


@contextlib.contextmanager
def _outbox_lock(outbox_path: str):
    lock_path = outbox_path + LOCK_SUFFIX
    fd = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)


def _rotate(outbox_path: str) -> str | None:
    """Atomically move OUTBOX → INFLIGHT. Returns INFLIGHT path or None."""
    inflight = outbox_path + INFLIGHT_SUFFIX
    with _outbox_lock(outbox_path):
        if os.path.exists(inflight) and os.path.getsize(inflight) > 0:
            # A previous run crashed mid-flush; re-process the existing inflight.
            return inflight
        if not os.path.exists(outbox_path) or os.path.getsize(outbox_path) == 0:
            return None
        os.rename(outbox_path, inflight)
        # Recreate empty outbox so next writer doesn't get a "no such file".
        open(outbox_path, "a").close()
    return inflight


def _reprepend(outbox_path: str, leftover: list[str]) -> None:
    """Put failed lines back at the head of the outbox under flock."""
    if not leftover:
        return
    with _outbox_lock(outbox_path):
        existing = ""
        if os.path.exists(outbox_path):
            with open(outbox_path) as f:
                existing = f.read()
        with open(outbox_path, "w") as f:
            for line in leftover:
                if not line.endswith("\n"):
                    line += "\n"
                f.write(line)
            f.write(existing)


def _append_dead(outbox_path: str, line: str, reason: str) -> None:
    dead_path = outbox_path + DEAD_SUFFIX
    record = {"reason": reason, "ts": time.time(), "line": line}
    with open(dead_path, "a") as f:
        f.write(json.dumps(record) + "\n")


# ─── Batching ──────────────────────────────────────────────────────────────


def _read_envelopes(path: str) -> Iterable[tuple[str, dict[str, Any]]]:
    with open(path) as f:
        for raw in f:
            stripped = raw.strip()
            if not stripped:
                continue
            try:
                env = json.loads(stripped)
            except json.JSONDecodeError as e:
                yield stripped, {"_malformed": str(e)}
                continue
            yield stripped, env


def _group_key(env: dict[str, Any]) -> tuple[str, str | None]:
    """Group envelopes so each batch POST is homogeneous in identity.

    The endpoint reads a single X-Host-Id / X-Session-Id from the
    request header; mixing envelopes with different identities into one
    batch would write the wrong header for some of them. Group by the
    identity field that drives the request:

      - sweep_*       → (kind, sweep_id)        endpoint path or X-Host-Id
      - finding       → (kind, session_id)      X-Session-Id header
      - global_finding/strategy → (kind, session_id) — strategy is single-record
                        anyway; group key still keeps siblings together
      - everything else (run-scoped) → (kind, run_id)
    """
    kind = env.get("kind", "")
    if kind in {"sweep_start", "sweep_finish", "sweep_test", "sweep_progress"}:
        return (kind, env.get("sweep_id"))
    if kind in {"finding", "global_finding", "strategy"}:
        return (kind, env.get("session_id"))
    return (kind, env.get("run_id"))


def _endpoint_for(kind: str, run_id: str | None, sweep_id: str | None) -> str | None:
    """Map kind → relative URL path. Returns None if the kind is unsupported
    by the server (callers should park it in dead.jsonl)."""
    if kind == "run_start":
        return "/ingest/runs"
    if kind == "run_finish":
        return f"/ingest/runs/{run_id}"
    if kind == "turn":
        return f"/ingest/runs/{run_id}/turns"
    if kind == "resource":
        return f"/ingest/runs/{run_id}/resources"
    if kind == "test":
        return f"/ingest/runs/{run_id}/tests"
    if kind == "finding":
        return "/ingest/findings"
    if kind == "global_finding":
        return "/ingest/global_findings"
    if kind == "strategy":
        return "/ingest/strategy"
    if kind == "sweep_start":
        return "/ingest/sweeps"
    if kind == "sweep_finish":
        return f"/ingest/sweeps/{sweep_id}"
    if kind == "sweep_test":
        return f"/ingest/sweeps/{sweep_id}/tests"
    if kind == "sweep_progress":
        return f"/ingest/sweeps/{sweep_id}/progress"
    if kind == "evaluation":
        return "/ingest/evaluations"
    if kind == "blob":
        return "/ingest/blobs"
    return None


def _request_for(
    kind: str, envs: list[dict[str, Any]]
) -> tuple[str, dict[str, Any] | list[dict[str, Any]]]:
    """Return (http_method, body) for a batched group of one kind."""
    payloads = [e["payload"] for e in envs]
    if kind == "run_start":
        # POST /ingest/runs is single-record (UPSERT one run at a time);
        # the flusher sends one POST per envelope in this group.
        return ("POST", payloads[0])
    if kind == "run_finish":
        return ("PATCH", payloads[0])
    if kind == "sweep_start":
        return ("POST", payloads[0])
    if kind == "sweep_finish":
        return ("PATCH", payloads[0])
    if kind == "strategy":
        return ("POST", payloads[0])
    if kind == "blob":
        return ("POST", payloads[0])
    # Batch endpoints take a list.
    return ("POST", payloads)


def _headers(token: str, env: dict[str, Any]) -> dict[str, str]:
    h = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    if env.get("host_id"):
        h["X-Host-Id"] = str(env["host_id"])
    if env.get("session_id"):
        h["X-Session-Id"] = str(env["session_id"])
    return h


# ─── Flush loop ────────────────────────────────────────────────────────────


def flush_once(outbox_path: str, base_url: str, token: str) -> tuple[int, int]:
    """One full pass over the inflight file. Returns (sent, failed)."""
    inflight = _rotate(outbox_path)
    if inflight is None:
        return (0, 0)

    raws: list[str] = []
    envs: list[dict[str, Any]] = []
    for raw, env in _read_envelopes(inflight):
        if env.get("_malformed"):
            _append_dead(outbox_path, raw, env["_malformed"])
            continue
        raws.append(raw)
        envs.append(env)

    if not envs:
        os.remove(inflight)
        return (0, 0)

    # Group while preserving order between groups using insertion order.
    groups: dict[tuple[str, str | None], list[tuple[str, dict[str, Any]]]] = (
        defaultdict(list)
    )
    for raw, env in zip(raws, envs):
        groups[_group_key(env)].append((raw, env))

    sent = 0
    leftover: list[str] = []
    backoff = INITIAL_BACKOFF
    session = requests.Session()

    for (kind, _), items in groups.items():
        # Endpoint/method/body depend on the FIRST envelope's identity.
        first_raw, first_env = items[0]
        path = _endpoint_for(kind, first_env.get("run_id"), first_env.get("sweep_id"))
        if path is None:
            for raw, _ in items:
                _append_dead(outbox_path, raw, f"unknown kind: {kind}")
            continue

        # Some kinds are single-record endpoints. POST one at a time so a
        # failure on one doesn't taint later siblings.
        single_record_kinds = {
            "run_start",
            "run_finish",
            "sweep_start",
            "sweep_finish",
            "strategy",
            "blob",
        }

        if kind in single_record_kinds:
            for raw, env in items:
                ok, fatal = _post(
                    session,
                    base_url,
                    path,
                    env,
                    token,
                    method="PATCH"
                    if kind in {"run_finish", "sweep_finish"}
                    else "POST",
                    body=env["payload"],
                )
                if ok:
                    sent += 1
                elif fatal:
                    _append_dead(outbox_path, raw, "4xx from server")
                else:
                    leftover.append(raw)
                    backoff = min(backoff * 2, MAX_BACKOFF)
            continue

        # Batch endpoints: chunk to BATCH_SIZE.
        for i in range(0, len(items), BATCH_SIZE):
            chunk = items[i : i + BATCH_SIZE]
            chunk_raws = [r for r, _ in chunk]
            chunk_envs = [e for _, e in chunk]
            method, body = _request_for(kind, chunk_envs)
            ok, fatal = _post(
                session, base_url, path, chunk_envs[0], token, method=method, body=body
            )
            if ok:
                sent += len(chunk)
            elif fatal:
                for raw in chunk_raws:
                    _append_dead(outbox_path, raw, "4xx from server")
            else:
                leftover.extend(chunk_raws)
                backoff = min(backoff * 2, MAX_BACKOFF)

    if leftover:
        _reprepend(outbox_path, leftover)
        time.sleep(backoff)
    os.remove(inflight)
    return (sent, len(leftover))


def _post(
    session: requests.Session,
    base_url: str,
    path: str,
    env: dict[str, Any],
    token: str,
    *,
    method: str,
    body: Any,
) -> tuple[bool, bool]:
    """Returns (ok, fatal). fatal=True for 4xx (drop, do not retry)."""
    url = base_url.rstrip("/") + path
    try:
        resp = session.request(
            method,
            url,
            headers=_headers(token, env),
            data=json.dumps(body),
            timeout=HTTP_TIMEOUT,
        )
    except requests.RequestException as e:
        logger.warning("network error %s %s: %s", method, url, e)
        return (False, False)

    if 200 <= resp.status_code < 300:
        return (True, False)
    if 400 <= resp.status_code < 500:
        logger.warning("4xx %s %s: %s", method, url, resp.text[:500])
        return (False, True)
    logger.warning("5xx %s %s: %s", method, url, resp.text[:500])
    return (False, False)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--outbox", default=os.environ.get("AGENT_OUTBOX_PATH", DEFAULT_OUTBOX)
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="One flush pass and exit (for cron / tests).",
    )
    parser.add_argument(
        "--interval",
        type=float,
        default=2.0,
        help="Seconds between passes when running as daemon (default: 2)",
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] outbox_flush: %(message)s",
    )

    cfg = _load_env()
    base_url = os.environ.get("AGENT_INGEST_URL") or cfg.get("AGENT_INGEST_URL")
    token = os.environ.get("AGENT_INGEST_TOKEN") or cfg.get("AGENT_INGEST_TOKEN")
    if not base_url or not token:
        logger.error(
            "AGENT_INGEST_URL and AGENT_INGEST_TOKEN must be set "
            "(in ~/.agentic-fuzz-sync.env or environment)"
        )
        sys.exit(2)

    if args.once:
        sent, failed = flush_once(args.outbox, base_url, token)
        logger.info("flush_once: sent=%d retry=%d", sent, failed)
        return

    while True:
        try:
            sent, failed = flush_once(args.outbox, base_url, token)
            if sent or failed:
                logger.info("flush: sent=%d retry=%d", sent, failed)
        except Exception as e:
            logger.exception("flush_once raised: %s", e)
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
