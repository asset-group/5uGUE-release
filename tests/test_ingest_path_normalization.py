"""Regression tests for worker→master path normalization in `dashboard.ingest`.

Workers post `app_log_path`, `runtime_log_path`, `metrics_png_path`, and
`resource_metrics_png_path` as their *own* filesystem paths (e.g.
`<WDISSECTOR_PATH>/.../logs/<host>/<run>_app_<ts>.log`). After
rsync the file is on the master at `<master_AGENT_PATH>/logs/<host>/...`.
If the server stores the worker path verbatim, `data_loader.parse_reasoning()`
opens a path that doesn't exist and returns `[]` — the dashboard renders
the run with no reasoning blocks.

This caused run `7bbeb73b` (the canary that drove this fix) to render
empty after the storage-server cutover. `scripts/backfill_to_db.py`
already had the rewrite (`_normalize_path_to_master`); the live ingest
path skipped it.

These tests run without a database — they exercise the pure
normalization helper plus a smoke test that confirms the helper is
called from `post_run` (via patching).
"""

from __future__ import annotations

import os
import sys
from unittest.mock import MagicMock, patch

import pytest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(TESTS_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

os.environ.setdefault("AGENT_INGEST_TOKEN", "test-token")
os.environ.setdefault("PG_DSN", "postgresql://x:x@127.0.0.1/x")

# Stub psycopg's pool boot so importing dashboard.ingest doesn't try to
# connect to a real DB.
sys.modules.setdefault("psycopg_pool", MagicMock())

fastapi = pytest.importorskip("fastapi")

from dashboard import ingest  # noqa: E402


@pytest.fixture(autouse=True)
def fixed_master_root(monkeypatch):
    """Patch the module-level _MASTER_AGENT_PATH to a known value.
    Without this, _MASTER_AGENT_PATH is captured at import time from
    os.environ['AGENT_PATH'] or os.getcwd(), and earlier tests in the
    same pytest run can leave it as the dev box's repo path."""
    monkeypatch.setattr(ingest, "_MASTER_AGENT_PATH", "/srv/agentfuzz")


_normalize_path_for_master = ingest._normalize_path_for_master


# ─── Helper unit tests ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "value, host, root, expected",
    [
        # Worker path → master-rooted path with same basename.
        (
            "/home/worker/wdissector/modules/agentic-fuzz/logs/host-a/7bbeb73b_app_20260429-110000.log",
            "host-a",
            "logs",
            "/srv/agentfuzz/logs/host-a/7bbeb73b_app_20260429-110000.log",
        ),
        # Worker runtime_logs path → master runtime_logs.
        (
            "/home/alice/repo/runtime_logs/host-a/7bbeb73b_manifest.json",
            "host-a",
            "runtime_logs",
            "/srv/agentfuzz/runtime_logs/host-a/7bbeb73b_manifest.json",
        ),
        # Already-master-rooted path is left alone (idempotent on retry).
        (
            "/srv/agentfuzz/logs/host-a/7bbeb73b_app_20260429-110000.log",
            "host-a",
            "logs",
            "/srv/agentfuzz/logs/host-a/7bbeb73b_app_20260429-110000.log",
        ),
        # PNG with no extension change.
        (
            "/root/x/runtime_logs/h1/agent_metrics_aa11.png",
            "h1",
            "runtime_logs",
            "/srv/agentfuzz/runtime_logs/h1/agent_metrics_aa11.png",
        ),
    ],
)
def test_normalize_rewrites_worker_paths(value, host, root, expected):
    assert _normalize_path_for_master(value, host, root) == expected


def test_normalize_passes_through_empty():
    assert _normalize_path_for_master(None, "any", "logs") is None
    assert _normalize_path_for_master("", "any", "logs") == ""


def test_normalize_legacy_host_unchanged():
    """The `_legacy` host represents flat-layout pre-cutover files —
    backfill leaves them as-is, and so do we."""
    src = "/some/old/place/runtime_logs/aa11_manifest.json"
    assert _normalize_path_for_master(src, "_legacy", "runtime_logs") == src


# ─── End-to-end: post_run actually rewrites + persists the master path ─────


def test_post_run_persists_normalized_paths():
    """Confirms the helper is wired into the SQL handler — not just defined.

    The earlier silent regression was that `_normalize_path_to_master`
    existed in `backfill_to_db.py` but the live POST handler ignored it.
    This test catches that class of mistake by intercepting the SQL
    arguments and asserting the four path columns are master-rooted.
    """
    # Capture the parameters passed to cur.execute in post_run.
    captured = {}

    class FakeCursor:
        def execute(self, sql, params=None):
            if params is not None and "INSERT INTO run" in sql:
                # Position of the four path fields in the INSERT VALUES tuple
                # (see post_run): (run_id, session_id, host_id, device, protocol,
                # model, max_turns, timestamp_str, started_at, app_log,
                # runtime_log, metrics_png, resource_metrics_png).
                captured["app_log_path"] = params[10]
                captured["runtime_log_path"] = params[11]
                captured["metrics_png_path"] = params[12]
                captured["resource_metrics_png_path"] = params[13]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class FakeConn:
        def cursor(self):
            return FakeCursor()

        def commit(self):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    class FakePool:
        def connection(self):
            return FakeConn()

    # Bypass the host upsert path-vs-DB plumbing.
    with (
        patch.object(ingest, "get_pool", return_value=FakePool()),
        patch.object(ingest, "_upsert_host"),
    ):
        body = ingest.RunStart(
            run_id="7bbeb73b",
            session_id="7bbeb73b-x",
            host_id="host-a",
            device="mediatek",
            protocol="fiveg",
            version="v3",
            model="anthropic/claude-sonnet-4.6",
            max_turns=60,
            timestamp="20260429-111000",
            app_log_path="/home/worker/wdissector/modules/agentic-fuzz/logs/host-a/7bbeb73b_app_20260429-110000.log",
            runtime_log_path="/home/worker/wdissector/modules/agentic-fuzz/runtime_logs/host-a/7bbeb73b_runtime_20260429-110000.log",
            metrics_png_path="/home/worker/wdissector/modules/agentic-fuzz/runtime_logs/host-a/agent_metrics_7bbeb73b.png",
            resource_metrics_png_path="/home/worker/wdissector/modules/agentic-fuzz/runtime_logs/host-a/resources_7bbeb73b.png",
        )
        ingest.post_run(body)

    # Every path field that hit the DB must be rooted at the master's
    # AGENT_PATH (set to /srv/agentfuzz at module import in this test file).
    for field, value in captured.items():
        assert value is not None, f"{field} was None"
        assert value.startswith("/srv/agentfuzz/"), (
            f"{field}={value!r} was not rewritten to master root — "
            "the live ingest path probably bypassed _normalize_run_paths."
        )
        # Basename must survive the rewrite.
        assert os.path.basename(value).startswith("7bbeb73b") or os.path.basename(
            value
        ) in {
            "agent_metrics_7bbeb73b.png",
            "resources_7bbeb73b.png",
        }, f"{field} lost its basename: {value!r}"
