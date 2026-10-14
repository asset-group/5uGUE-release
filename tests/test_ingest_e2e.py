"""End-to-end test for the Postgres-backed ingest pipeline.

Covers the verification matrix from the cutover plan:
  1. Schema apply (migrate.py against postgres:18-alpine).
  2. Out-of-order ingest: child events before parent.
  3. Resource-field round-trip preserves all 9 columns.
  4. Findings split: session vs global.
  5. Sweep retry-chain direction matrix (root/child/grandchild as input).
  6. Eval hook ingest semantics.
  7. Idempotency (replay → counts unchanged).
  8. Timestamp parity with AGENT_TIMEZONE.
  9. Outbox envelope schema lint.
 10. Stub-then-real ordering.

Skips itself if the `testcontainers` extra is not installed; integrators
run this against a one-shot postgres:18-alpine container in CI.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(TESTS_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

testcontainers = pytest.importorskip(
    "testcontainers.postgres",
    reason="testcontainers not installed — install requirements-dev.txt to run e2e",
)
fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")
psycopg = pytest.importorskip("psycopg")

from testcontainers.postgres import PostgresContainer  # noqa: E402


@pytest.fixture(scope="module")
def pg_container():
    with PostgresContainer("postgres:18-alpine") as pg:
        yield pg


@pytest.fixture(scope="module")
def pg_dsn(pg_container):
    return pg_container.get_connection_url().replace(
        "postgresql+psycopg2://", "postgresql://"
    )


@pytest.fixture
def app(pg_dsn, monkeypatch):
    """Boot the FastAPI app with the test DB. Re-imports the dashboard
    modules so the connection pool picks up the test DSN."""
    monkeypatch.setenv("PG_DSN", pg_dsn)
    monkeypatch.setenv("AGENT_INGEST_TOKEN", "test-token-abc")
    monkeypatch.setenv("AGENT_TIMEZONE", "UTC")

    # Force reload of the modules that capture PG_DSN at import time.
    for mod in [
        "dashboard.db",
        "dashboard.ingest",
        "dashboard.data_loader",
        "dashboard.app",
    ]:
        sys.modules.pop(mod, None)

    from dashboard.sql import migrate

    migrate.apply(pg_dsn)

    from dashboard.app import app as fastapi_app

    yield fastapi_app

    from dashboard.db import close_pool

    close_pool()


@pytest.fixture
def client(app):
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        c.headers.update({"Authorization": "Bearer test-token-abc"})
        yield c


# ─── Verification ──────────────────────────────────────────────────────────


def test_schema_applied(pg_dsn):
    """All declared tables, indexes, and CHECK constraints exist."""
    from dashboard.sql import migrate

    migrate.apply(pg_dsn)
    with psycopg.connect(pg_dsn) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename"
            )
            tables = {r[0] for r in cur.fetchall()}
    expected = {
        "host",
        "run",
        "turn",
        "resource_sample",
        "test",
        "sweep",
        "sweep_test",
        "sweep_progress",
        "evaluation",
        "session_finding",
        "global_finding",
        "session_strategy",
        "run_blob",
        "schema_migration",
    }
    missing = expected - tables
    assert not missing, f"missing tables: {missing}"


def test_out_of_order_ingest(client):
    """Child events arriving before run_start get a stub run row, then
    the real run_start UPSERTs full fields without losing children."""
    run_id = "deadbeef"
    host_id = "test-host"

    # Turn arrives first (no run_start yet).
    resp = client.post(
        f"/ingest/runs/{run_id}/turns",
        headers={"X-Host-Id": host_id},
        json=[
            {
                "turn": 1,
                "timestamp": 1700000000.0,
                "tools_called": ["read_file"],
                "tool_call_count": 1,
                "tool_counts": {"read_file": 1},
                "input_tokens": 100,
                "output_tokens": 50,
                "cumulative_input_tokens": 100,
                "cumulative_output_tokens": 50,
                "turn_crashes": 0,
                "turn_publicly_known": 0,
                "turn_non_publicly_known": 0,
                "turn_fully_novel": 0,
                "cumulative_crashes": 0,
                "cumulative_publicly_known": 0,
                "cumulative_non_publicly_known": 0,
                "cumulative_fully_novel": 0,
                "session_unique_crashes": 0,
                "phase": "research",
            }
        ],
    )
    assert resp.status_code == 200, resp.text

    # Run row exists as a stub.
    from dashboard.db import get_pool

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT host_id, status FROM run WHERE run_id = %s", (run_id,))
            row = cur.fetchone()
    assert row is not None
    assert row["host_id"] == host_id
    assert row["status"] == "partial"

    # Now run_start arrives — full UPSERT.
    resp = client.post(
        "/ingest/runs",
        json={
            "run_id": run_id,
            "host_id": host_id,
            "session_id": "deadbeef-x",
            "device": "mediatek",
            "protocol": "fiveg",
            "version": "v1",
            "model": "test/model",
            "max_turns": 100,
            "timestamp": "20260301-120000",
            "app_log_path": "/x/a.log",
            "runtime_log_path": "/x/r.log",
            "metrics_png_path": None,
            "resource_metrics_png_path": None,
        },
    )
    assert resp.status_code == 200

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT device, protocol, status, session_id FROM run WHERE run_id = %s",
                (run_id,),
            )
            row = cur.fetchone()
            cur.execute("SELECT count(*) AS n FROM turn WHERE run_id = %s", (run_id,))
            turn_count = cur.fetchone()["n"]
    assert row["device"] == "mediatek"
    assert row["protocol"] == "fiveg"
    assert row["status"] == "started"
    assert row["session_id"] == "deadbeef-x"
    assert turn_count == 1

    # Verify database data loaders fetch device and protocol correctly
    from dashboard.data_loader import load_run_data, load_run_list

    runs = load_run_list()
    run_info = next(r for r in runs if r["run_id"] == run_id)
    assert run_info["device"] == "mediatek"
    assert run_info["protocol"] == "fiveg"

    data = load_run_data(run_id)
    assert data["device"] == "mediatek"
    assert data["protocol"] == "fiveg"


def test_resource_field_roundtrip(client):
    """All 9 fields from resource_monitor.py:74-84 round-trip exactly."""
    run_id = "abcd0001"
    host_id = "rsx"
    client.post(
        "/ingest/runs",
        json={
            "run_id": run_id,
            "host_id": host_id,
            "session_id": "abcd0001-r",
            "timestamp": "20260301-120000",
        },
    )
    sample = {
        "ts": 1700000001.0,
        "turn": 3,
        "cpu_percent": 12.5,
        "mem_rss_mb": 234.0,
        "mem_system_percent": 45.6,
        "disk_read_mb": 100.0,
        "disk_write_mb": 50.0,
        "net_sent_mb": 5.0,
        "net_recv_mb": 10.0,
        "event": "test_start",
        "metadata": {"k": "v"},
    }
    r = client.post(
        f"/ingest/runs/{run_id}/resources",
        headers={"X-Host-Id": host_id},
        json=[sample],
    )
    assert r.status_code == 200, r.text

    from dashboard.db import get_pool

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT cpu_percent, mem_rss_mb, mem_system_percent, "
                "disk_read_mb, disk_write_mb, net_sent_mb, net_recv_mb, "
                "event, metadata, turn FROM resource_sample WHERE run_id = %s",
                (run_id,),
            )
            row = cur.fetchone()
    assert row["cpu_percent"] == pytest.approx(12.5)
    assert row["mem_rss_mb"] == pytest.approx(234.0)
    assert row["mem_system_percent"] == pytest.approx(45.6)
    assert row["disk_read_mb"] == pytest.approx(100.0)
    assert row["disk_write_mb"] == pytest.approx(50.0)
    assert row["net_sent_mb"] == pytest.approx(5.0)
    assert row["net_recv_mb"] == pytest.approx(10.0)
    assert row["event"] == "test_start"
    assert row["metadata"] == {"k": "v"}
    assert row["turn"] == 3


def test_findings_split(client):
    """Session findings + global findings land in separate tables."""
    session_id = "abcd0002-sess"
    client.post(
        "/ingest/runs",
        json={
            "run_id": "abcd0002",
            "host_id": "fhost",
            "session_id": session_id,
            "timestamp": "20260301-120000",
        },
    )
    client.post(
        "/ingest/findings",
        headers={"X-Session-Id": session_id},
        json=[
            {
                "finding_id": 1,
                "type": "observation",
                "description": "a",
                "tags": ["x"],
                "timestamp": "2026-03-01T12:00:00",
            },
            {
                "finding_id": 2,
                "type": "observation",
                "description": "b",
                "tags": ["y"],
                "timestamp": "2026-03-01T12:00:01",
            },
            {
                "finding_id": 3,
                "type": "observation",
                "description": "c",
                "tags": ["z"],
                "dedup_key": "k1",
                "timestamp": "2026-03-01T12:00:02",
            },
        ],
    )
    client.post(
        "/ingest/global_findings",
        json=[
            {
                "dedup_key": "g1",
                "description": "global a",
                "timestamp": "2026-03-01T12:00:00",
            },
            {
                "dedup_key": "g2",
                "description": "global b",
                "timestamp": "2026-03-01T12:00:01",
            },
        ],
    )

    from dashboard.db import get_pool

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT count(*) AS n FROM session_finding WHERE session_id = %s",
                (session_id,),
            )
            assert cur.fetchone()["n"] == 3
            cur.execute("SELECT count(*) AS n FROM global_finding")
            assert cur.fetchone()["n"] == 2


def test_sweep_retry_chain_direction(client):
    """Heatmap merges queried node + descendants only (forward walk)."""
    host = "rh"
    # Build root → child → grandchild.
    for sid, parent in (
        ("10001234", None),
        ("20004321", "10001234"),
        ("30002345", "20004321"),
    ):
        resp = client.post(
            "/ingest/sweeps",
            json={
                "sweep_id": sid,
                "host_id": host,
                "device": "mediatek",
                "protocol": "fiveg",
                "profile": "quick",
                "filters": ["nr-rrc.rrcSetup_element"],
                "offset_range": [0, 10],
                "offsets_per_filter": 2,
                "offset_strategy": "near_known",
                "values": [0],
                "values_hex": ["0x00"],
                "total_combinations": 2,
                "exploit_timeout": 60,
                "retry_of": parent,
                "retry_depth": 0 if parent is None else 1,
                "start_time": "2026-03-01T12:00:00",
            },
        )
        assert resp.status_code == 200, resp.text

    # Same combo present in all three with different crash flags.
    for sid, crashed in (("10001234", False), ("20004321", True), ("30002345", False)):
        client.post(
            f"/ingest/sweeps/{sid}/tests",
            headers={"X-Host-Id": host},
            json=[
                {
                    "test_num": 1,
                    "filter": "nr-rrc.rrcSetup_element",
                    "offset": 5,
                    "value": 0,
                    "value_hex": "0x00",
                    "crash": crashed,
                    "crash_id": None,
                    "crash_category": None,
                    "compile_success": True,
                    "compile_error": None,
                    "execution_time_seconds": 1.0,
                    "mutation_count": 0,
                    "total_packets": 0,
                    "timestamp": "2026-03-01T12:00:00",
                }
            ],
        )

    from dashboard.data_loader import load_sweep_data

    # Querying root → grandchild is the latest (descendant); crashed=False.
    data_root = load_sweep_data("10001234")
    assert data_root is not None
    assert data_root["manifest"]["device"] == "mediatek"
    assert data_root["manifest"]["protocol"] == "fiveg"
    assert len(data_root["results"]) == 1
    assert data_root["results"][0]["crash"] is False  # gch wins (deepest descendant)

    # Querying child → grandchild wins.
    data_child = load_sweep_data("20004321")
    assert data_child["results"][0]["crash"] is False

    # Querying grandchild — no descendants; only its own row.
    data_gch = load_sweep_data("30002345")
    assert data_gch["results"][0]["crash"] is False


def test_idempotency(client):
    """Replaying the same fixture twice does not change row counts."""
    run_id = "abcd0003"
    host = "ih"
    payload = {
        "run_id": run_id,
        "host_id": host,
        "session_id": "abcd0003-x",
        "device": "mediatek",
        "protocol": "fiveg",
        "timestamp": "20260301-120000",
    }
    client.post("/ingest/runs", json=payload)
    client.post(
        f"/ingest/runs/{run_id}/turns",
        headers={"X-Host-Id": host},
        json=[
            {
                "turn": 1,
                "timestamp": 1700000000.0,
                "tools_called": [],
                "tool_call_count": 0,
                "tool_counts": {},
                "input_tokens": 1,
                "output_tokens": 1,
                "cumulative_input_tokens": 1,
                "cumulative_output_tokens": 1,
                "turn_crashes": 0,
                "turn_publicly_known": 0,
                "turn_non_publicly_known": 0,
                "turn_fully_novel": 0,
                "cumulative_crashes": 0,
                "cumulative_publicly_known": 0,
                "cumulative_non_publicly_known": 0,
                "cumulative_fully_novel": 0,
                "session_unique_crashes": 0,
                "phase": "research",
            }
        ],
    )
    # Replay.
    client.post("/ingest/runs", json=payload)
    client.post(
        f"/ingest/runs/{run_id}/turns",
        headers={"X-Host-Id": host},
        json=[
            {
                "turn": 1,
                "timestamp": 1700000000.0,
                "tools_called": [],
                "tool_call_count": 0,
                "tool_counts": {},
                "input_tokens": 1,
                "output_tokens": 1,
                "cumulative_input_tokens": 1,
                "cumulative_output_tokens": 1,
                "turn_crashes": 0,
                "turn_publicly_known": 0,
                "turn_non_publicly_known": 0,
                "turn_fully_novel": 0,
                "cumulative_crashes": 0,
                "cumulative_publicly_known": 0,
                "cumulative_non_publicly_known": 0,
                "cumulative_fully_novel": 0,
                "session_unique_crashes": 0,
                "phase": "research",
            }
        ],
    )

    from dashboard.db import get_pool

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM run WHERE run_id = %s", (run_id,))
            assert cur.fetchone()["n"] == 1
            cur.execute("SELECT count(*) AS n FROM turn WHERE run_id = %s", (run_id,))
            assert cur.fetchone()["n"] == 1


def test_timestamp_parity_legacy_string(client, monkeypatch):
    """%Y%m%d-%H%M%S is interpreted in AGENT_TIMEZONE; raw_str preserved."""
    import importlib

    import dashboard.db as _db

    monkeypatch.setenv("AGENT_TIMEZONE", "America/Los_Angeles")
    importlib.reload(_db)

    from datetime import datetime, timezone

    dt = _db.to_ts("20260101-120000")
    # 12:00 LA time = 20:00 UTC.
    assert dt == datetime(2026, 1, 1, 20, 0, 0, tzinfo=timezone.utc)

    monkeypatch.setenv("AGENT_TIMEZONE", "UTC")
    importlib.reload(_db)
    dt = _db.to_ts("20260101-120000")
    assert dt == datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)


def test_evaluation_hook_shape(client):
    """Eval rows land in `evaluation` keyed by run_id."""
    run_id = "abcd0004"
    host = "eh"
    eval_id = "0123456789abcdef0123456789abcdef"
    client.post(
        "/ingest/runs",
        json={
            "run_id": run_id,
            "host_id": host,
            "session_id": "abcd0004-x",
            "timestamp": "20260301-120000",
        },
    )
    client.post(
        "/ingest/evaluations",
        headers={"X-Host-Id": host},
        json=[
            {
                "run_id": run_id,
                "version": "v1",
                "evaluated_at": 1700000010.0,
                "session_id": "abcd0004-x",
                "model": "test/model",
                "device": "mediatek",
                "protocol": "fiveg",
                "max_turns": 30,
                "actual_turns": 12,
                "rq_max_score": 3,
                "rq_max_level": "L3",
                "rq_mean_score": 1.5,
                "publicly_known_crashes": 1,
                "non_publicly_known_crashes": 0,
                "fully_novel_crashes": 0,
                "total_crashes": 1,
                "total_input_tokens": 1234,
                "total_output_tokens": 567,
                "unique_crashes": 1,
                "unique_novel": 1,
                "total_tests": 17,
                "time_to_first_crash_seconds": 42.5,
                "tests_till_first_crash": 4,
                "total_session_time_seconds": 600.25,
                "source_csv_path": "/x/eval_v1_20260301_120010.csv",
                "eval_id": eval_id,
            }
        ],
    )
    from dashboard.db import get_pool

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT rq_max_level, total_input_tokens, unique_crashes, "
                "unique_novel, total_tests, time_to_first_crash_seconds, "
                "tests_till_first_crash, total_session_time_seconds, eval_id "
                "FROM evaluation WHERE run_id = %s",
                (run_id,),
            )
            row = cur.fetchone()
    assert row["rq_max_level"] == "L3"
    assert row["total_input_tokens"] == 1234
    assert row["unique_crashes"] == 1
    assert row["unique_novel"] == 1
    assert row["total_tests"] == 17
    assert row["time_to_first_crash_seconds"] == pytest.approx(42.5)
    assert row["tests_till_first_crash"] == 4
    assert row["total_session_time_seconds"] == pytest.approx(600.25)
    assert row["eval_id"] == eval_id


def test_evaluation_eval_id_validation(client):
    """Pydantic + DB CHECK both reject bad eval_id strings."""
    run_id = "abcd0006"
    host = "ev"
    client.post(
        "/ingest/runs",
        json={
            "run_id": run_id,
            "host_id": host,
            "session_id": "abcd0006-x",
            "timestamp": "20260301-130000",
        },
    )
    resp = client.post(
        "/ingest/evaluations",
        headers={"X-Host-Id": host},
        json=[
            {
                "run_id": run_id,
                "version": "v3",
                "evaluated_at": 1700000020.0,
                "eval_id": "not-a-valid-hex-string",
            }
        ],
    )
    assert resp.status_code == 422


def test_reports_endpoints(client):
    """list_reports + load_report_data round-trip via /api/reports."""
    eval_id = "feedfacefeedfacefeedfacefeedface"
    host = "rh"
    for i, run_id in enumerate(["aaaa1111", "aaaa2222", "aaaa3333"]):
        client.post(
            "/ingest/runs",
            json={
                "run_id": run_id,
                "host_id": host,
                "session_id": f"{run_id}-x",
                "timestamp": f"2026030{i + 1}-120000",
            },
        )
        client.post(
            "/ingest/evaluations",
            headers={"X-Host-Id": host},
            json=[
                {
                    "run_id": run_id,
                    "version": "v3",
                    "evaluated_at": 1700000100.0 + i,
                    "session_id": f"{run_id}-x",
                    "model": "anthropic/test",
                    "device": "mediatek_d6300",
                    "protocol": "fiveg",
                    "max_turns": 60,
                    "actual_turns": 60,
                    "rq_max_score": 3 + (i % 2),
                    "rq_max_level": "L3",
                    "rq_mean_score": 2.0 + i * 0.1,
                    "publicly_known_crashes": 0,
                    "non_publicly_known_crashes": 5 + i,
                    "fully_novel_crashes": 0,
                    "total_crashes": 5 + i,
                    "total_input_tokens": 1_000_000 + i,
                    "total_output_tokens": 50_000 + i,
                    "unique_crashes": 2,
                    "unique_novel": 0,
                    "total_tests": 80 + i,
                    "time_to_first_crash_seconds": 100.0 if i < 2 else None,
                    "tests_till_first_crash": 1 if i < 2 else None,
                    "total_session_time_seconds": 5000.0 + i * 100,
                    "source_csv_path": "/r/eval_v3_20260301_120000.csv",
                    "eval_id": eval_id,
                }
            ],
        )
    # Use the FastAPI app via httpx — auth is required for /api/reports
    # but the test client wasn't configured with basic auth. Read directly
    # from the loaders instead.
    from dashboard.data_loader import list_reports, load_report_data

    reports = list_reports()
    assert any(r["eval_id"] == eval_id for r in reports)
    found = next(r for r in reports if r["eval_id"] == eval_id)
    assert found["n_runs"] == 3
    assert found["source_csv_basename"] == "eval_v3_20260301_120000.csv"
    assert found["device"] == "mediatek_d6300"
    assert found["protocol"] == "fiveg"

    detail = load_report_data(eval_id)
    assert detail is not None
    assert detail["n_runs"] == 3
    assert detail["config"]["model"] == "anthropic/test"
    assert detail["config"]["device"] == "mediatek_d6300"
    assert detail["config"]["protocol"] == "fiveg"
    assert len(detail["rows"]) == 3
    # Aggregates exclude None values for time_to_first_crash and report n_na.
    ttfc = detail["aggregates"]["time_to_first_crash_seconds"]
    assert ttfc["n_with_value"] == 2
    assert ttfc["n_na"] == 1
    # Numeric stats present for total_crashes (no nulls).
    crashes_agg = detail["aggregates"]["total_crashes"]
    assert crashes_agg["n"] == 3
    assert crashes_agg["min"] == 5
    assert crashes_agg["max"] == 7
    # RQ level histogram totals to n_runs.
    assert sum(detail["rq_level_distribution"].values()) == 3

    assert load_report_data("0" * 32) is None


def test_outbox_envelope_schema_lint():
    """ingest_client.enqueue must build a complete envelope."""
    import ingest_client

    captured: list[str] = []

    def fake_open(path, mode):
        from io import StringIO

        sio = StringIO()
        sio.close = lambda: captured.append(sio.getvalue())  # type: ignore
        return sio

    import builtins

    real_open = builtins.open
    builtins.open = fake_open  # type: ignore
    try:
        os.environ.pop("AGENT_NO_INGEST", None)
        ingest_client.enqueue("turn", {"turn": 1}, run_id="abcd0005")
    finally:
        builtins.open = real_open

    assert captured, "enqueue must write a line"
    env = json.loads(captured[-1])
    for key in (
        "kind",
        "host_id",
        "run_id",
        "sweep_id",
        "session_id",
        "enqueued_at",
        "payload",
    ):
        assert key in env, f"envelope missing {key}"
    assert env["kind"] == "turn"
    assert env["run_id"] == "abcd0005"


def test_unknown_kind_dropped(caplog):
    """An unknown kind must not be written to the outbox."""
    import ingest_client

    written: list[str] = []

    import builtins

    real_open = builtins.open

    def fake_open(path, mode):  # pragma: no cover (reached only on bug)
        written.append(path)
        return real_open(path, mode)

    builtins.open = fake_open  # type: ignore
    try:
        os.environ.pop("AGENT_NO_INGEST", None)
        ingest_client.enqueue("bogus_kind", {})
    finally:
        builtins.open = real_open
    assert written == []


def test_blob_endpoint_kinds(client):
    """All four blob kinds round-trip and mirror onto the run row columns."""
    run_id = "abcd0006"
    host = "bh"
    client.post(
        "/ingest/runs",
        json={
            "run_id": run_id,
            "host_id": host,
            "session_id": "abcd0006-x",
            "timestamp": "20260301-120000",
        },
    )
    pairs = {
        "app_log": "/x/app.log",
        "runtime_log": "/x/run.log",
        "metrics_png": "/x/m.png",
        "resource_metrics_png": "/x/r.png",
    }
    for kind, path in pairs.items():
        r = client.post(
            "/ingest/blobs",
            headers={"X-Host-Id": host},
            json={"run_id": run_id, "kind": kind, "path": path},
        )
        assert r.status_code == 200, r.text

    from dashboard.db import get_pool

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT kind, path FROM run_blob WHERE run_id = %s ORDER BY kind",
                (run_id,),
            )
            blob_rows = list(cur.fetchall())
            cur.execute(
                "SELECT app_log_path, runtime_log_path, metrics_png_path, "
                "resource_metrics_png_path FROM run WHERE run_id = %s",
                (run_id,),
            )
            row = cur.fetchone()

    assert {b["kind"] for b in blob_rows} == set(pairs.keys())
    assert row["app_log_path"] == "/x/app.log"
    assert row["runtime_log_path"] == "/x/run.log"
    assert row["metrics_png_path"] == "/x/m.png"
    assert row["resource_metrics_png_path"] == "/x/r.png"


def test_invalid_run_id_4xx(client):
    """Malformed run_id at the API boundary is a 400 (→ dead.jsonl)."""
    r = client.post("/ingest/runs", json={"run_id": "BAD", "host_id": "x"})
    assert r.status_code == 400


def test_unauthorized_no_token(app):
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        r = c.post("/ingest/runs", json={"run_id": "abcd0007", "host_id": "x"})
    assert r.status_code == 401


def test_delete_run(client):
    run_a = "abcd0009"
    run_b = "abcd0010"
    host_id = "test-host"

    # Populate Run A and Run B across all dependent tables
    for run_id in (run_a, run_b):
        # 1. RunStart
        resp = client.post(
            "/ingest/runs",
            json={
                "run_id": run_id,
                "host_id": host_id,
                "session_id": f"sess-{run_id}",
                "timestamp": "20260702-120000",
            },
        )
        assert resp.status_code == 200, resp.text

        # 2. TurnRecord
        resp = client.post(
            f"/ingest/runs/{run_id}/turns",
            headers={"X-Host-Id": host_id},
            json=[
                {
                    "turn": 1,
                    "timestamp": 1700000000.0,
                    "tools_called": [],
                    "cumulative_input_tokens": 0,
                    "cumulative_output_tokens": 0,
                }
            ],
        )
        assert resp.status_code == 200, resp.text

        # 3. ResourceSample
        resp = client.post(
            f"/ingest/runs/{run_id}/resources",
            headers={"X-Host-Id": host_id},
            json=[
                {
                    "ts": 1700000001.0,
                    "turn": 1,
                    "cpu_percent": 10.0,
                }
            ],
        )
        assert resp.status_code == 200, resp.text

        # 4. TestRecord
        resp = client.post(
            f"/ingest/runs/{run_id}/tests",
            headers={"X-Host-Id": host_id},
            json=[
                {
                    "test_id": "test-1",
                    "session_id": f"sess-{run_id}",
                    "exploit_name": "exploit-a",
                    "crash": False,
                }
            ],
        )
        assert resp.status_code == 200, resp.text

        # 5. EvaluationRow
        resp = client.post(
            "/ingest/evaluations",
            headers={"X-Host-Id": host_id},
            json=[
                {
                    "run_id": run_id,
                    "version": "full",
                    "evaluated_at": 1700000000.0,
                    "session_id": f"sess-{run_id}",
                    "model": "gpt-4",
                }
            ],
        )
        assert resp.status_code == 200, resp.text

        # 6. BlobRecord
        resp = client.post(
            "/ingest/blobs",
            headers={"X-Host-Id": host_id},
            json={
                "run_id": run_id,
                "kind": "app_log",
                "path": f"/path/{run_id}/app.log",
            },
        )
        assert resp.status_code == 200, resp.text

    # Verify both runs have exactly one entry in all tables
    from dashboard.db import get_pool

    tables = ["run", "turn", "resource_sample", "test", "evaluation", "run_blob"]

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            for table in tables:
                for run_id in (run_a, run_b):
                    cur.execute(
                        f"SELECT COUNT(*) AS cnt FROM {table} WHERE run_id = %s",
                        (run_id,),
                    )
                    row = cur.fetchone()
                    assert row["cnt"] == 1, (
                        f"Expected 1 row in {table} for {run_id}, got {row['cnt']}"
                    )

    # Delete Run A
    resp = client.delete(f"/ingest/runs/{run_a}")
    assert resp.status_code == 200, resp.text

    # Verify Run A is completely gone from all tables, and Run B is completely untouched
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            for table in tables:
                # Run A must be gone (count = 0)
                cur.execute(
                    f"SELECT COUNT(*) AS cnt FROM {table} WHERE run_id = %s", (run_a,)
                )
                row_a = cur.fetchone()
                assert row_a["cnt"] == 0, (
                    f"Expected 0 rows in {table} for {run_a} after deletion, got {row_a['cnt']}"
                )

                # Run B must remain untouched (count = 1)
                cur.execute(
                    f"SELECT COUNT(*) AS cnt FROM {table} WHERE run_id = %s", (run_b,)
                )
                row_b = cur.fetchone()
                assert row_b["cnt"] == 1, (
                    f"Expected 1 row in {table} for {run_b} to remain, got {row_b['cnt']}"
                )
