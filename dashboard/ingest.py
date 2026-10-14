"""FastAPI router for worker → master ingest.

Mounted into `dashboard/app.py`. Endpoints are bearer-token gated by
`AGENT_INGEST_TOKEN` from `~/.agentic-fuzz-master.env`. All endpoints
upsert on natural keys so retries from the worker outbox are safe.

Two SQL patterns are used (see `dashboard/db.py` docstring):

- Full event (POST .../{turns,resources,tests,sweeps/.../tests,
  sweeps/.../progress,evaluations,findings,global_findings,blobs}):
    INSERT … ON CONFLICT (pk) DO UPDATE SET col = EXCLUDED.col
  for each column in the request payload.

- Partial PATCH (PATCH /ingest/runs/{run_id}, PATCH /ingest/sweeps/{sweep_id}):
  build the SET clause from keys present in the body. NEVER COALESCE —
  workers must be able to set columns to NULL via PATCH.

FK target rows (run, sweep) auto-create as `status='partial'` stubs when
a child event arrives first. The real start event later UPSERTs the full
fields. This is what makes out-of-order ingest safe; child events never
need to remember to re-include parent identity beyond the envelope.
"""

from __future__ import annotations

import json
import os
import re
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from dashboard.db import build_partial_update, get_pool, healthcheck, to_ts


router = APIRouter(prefix="/ingest", tags=["ingest"])


# ─── Auth ──────────────────────────────────────────────────────────────────


def _require_token(authorization: str = Header(default="")) -> None:
    expected = os.environ.get("AGENT_INGEST_TOKEN", "")
    if not expected:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AGENT_INGEST_TOKEN not configured on server",
        )
    prefix = "Bearer "
    if not authorization.startswith(prefix) or authorization[len(prefix) :] != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid bearer token"
        )


# ─── Pydantic models ───────────────────────────────────────────────────────
# Models match the worker outbox envelope `payload` shape. Identity fields
# (host_id, run_id, sweep_id, session_id) live on the envelope, not the
# payload — see ingest_client.py.


class Envelope(BaseModel):
    """Common envelope wrapping an event payload."""

    kind: str
    host_id: str
    run_id: Optional[str] = None
    sweep_id: Optional[str] = None
    session_id: Optional[str] = None
    enqueued_at: Optional[float] = None
    payload: dict[str, Any] = Field(default_factory=dict)


class RunStart(BaseModel):
    run_id: str
    host_id: str
    session_id: Optional[str] = None
    device: Optional[str] = None
    protocol: Optional[str] = None
    version: Optional[str] = None
    model: Optional[str] = None
    max_turns: Optional[int] = None
    timestamp: Optional[str] = None  # raw "%Y%m%d-%H%M%S" from manifest
    app_log_path: Optional[str] = None
    runtime_log_path: Optional[str] = None
    metrics_png_path: Optional[str] = None
    resource_metrics_png_path: Optional[str] = None


class RunPatch(BaseModel):
    """Partial update — only fields present are written."""

    session_id: Optional[str] = None
    device: Optional[str] = None
    protocol: Optional[str] = None
    version: Optional[str] = None
    model: Optional[str] = None
    max_turns: Optional[int] = None
    ended_at: Optional[float] = None
    status: Optional[str] = None
    app_log_path: Optional[str] = None
    runtime_log_path: Optional[str] = None
    metrics_png_path: Optional[str] = None
    resource_metrics_png_path: Optional[str] = None
    final_total_crashes: Optional[int] = None
    final_unique_crashes: Optional[int] = None
    final_publicly_known: Optional[int] = None
    final_non_publicly_known: Optional[int] = None
    final_fully_novel: Optional[int] = None
    total_input_tokens: Optional[int] = None
    total_output_tokens: Optional[int] = None

    model_config = {"extra": "ignore"}

    def present(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True)


class TurnRecord(BaseModel):
    turn: int
    timestamp: float
    tools_called: list[str] = Field(default_factory=list)
    tool_call_count: Optional[int] = None
    tool_counts: dict[str, int] = Field(default_factory=dict)
    input_tokens: Optional[int] = None
    output_tokens: Optional[int] = None
    cumulative_input_tokens: Optional[int] = None
    cumulative_output_tokens: Optional[int] = None
    turn_crashes: Optional[int] = None
    turn_publicly_known: Optional[int] = None
    turn_non_publicly_known: Optional[int] = None
    turn_fully_novel: Optional[int] = None
    cumulative_crashes: Optional[int] = None
    cumulative_publicly_known: Optional[int] = None
    cumulative_non_publicly_known: Optional[int] = None
    cumulative_fully_novel: Optional[int] = None
    session_unique_crashes: Optional[int] = None
    phase: Optional[str] = None
    error: Optional[str] = None


class ResourceSample(BaseModel):
    ts: float
    turn: Optional[int] = None
    cpu_percent: Optional[float] = None
    mem_rss_mb: Optional[float] = None
    mem_system_percent: Optional[float] = None
    disk_read_mb: Optional[float] = None
    disk_write_mb: Optional[float] = None
    net_sent_mb: Optional[float] = None
    net_recv_mb: Optional[float] = None
    event: Optional[str] = None
    metadata: Optional[dict[str, Any]] = None


class TestRecord(BaseModel):
    test_id: str
    session_id: Optional[str] = None
    exploit_name: Optional[str] = None
    exploit_code: Optional[str] = None
    exploit_hash: Optional[str] = None
    fuzz_description: Optional[str] = None
    crash: Optional[bool] = None
    crash_category: Optional[str] = None
    crash_id: Optional[str] = None
    new_states: Optional[int] = None
    new_transitions: Optional[int] = None
    compile_success: Optional[bool] = None
    execution_time_seconds: Optional[float] = None
    mutation_count: Optional[int] = None
    mutation_parse_warnings: Optional[list[str]] = None
    total_packets: Optional[int] = None
    timestamp: Optional[str] = None


class SessionFinding(BaseModel):
    finding_id: int
    type: Optional[str] = None
    description: Optional[str] = None
    related_tests: Optional[list[Any]] = None
    tags: Optional[list[str]] = None
    source_url: Optional[str] = None
    dedup_key: Optional[str] = None
    timestamp: Optional[str] = None


class GlobalFinding(BaseModel):
    dedup_key: str
    description: Optional[str] = None
    tags: Optional[list[str]] = None
    source_session: Optional[str] = None
    timestamp: Optional[str] = None


class SessionStrategy(BaseModel):
    session_id: str
    host_id: Optional[str] = None
    text: str


class SweepStart(BaseModel):
    sweep_id: str
    host_id: str
    device: Optional[str] = None
    protocol: Optional[str] = None
    profile: Optional[str] = None
    filters: Optional[list[str]] = None
    offset_range: Optional[list[int]] = None
    offsets_per_filter: Optional[int] = None
    offset_strategy: Optional[str] = None
    values: Optional[list[int]] = None
    values_hex: Optional[list[str]] = None
    total_combinations: Optional[int] = None
    exploit_timeout: Optional[int] = None
    retry_of: Optional[str] = None
    retry_depth: Optional[int] = None
    start_time: Optional[str] = None  # raw manifest start_time string


class SweepPatch(BaseModel):
    ended_at: Optional[float] = None
    status: Optional[str] = None
    total_combinations: Optional[int] = None

    model_config = {"extra": "ignore"}

    def present(self) -> dict[str, Any]:
        return self.model_dump(exclude_none=True)


class SweepTest(BaseModel):
    test_num: int
    filter: Optional[str] = None
    offset: Optional[int] = None
    value: Optional[int] = None
    value_hex: Optional[str] = None
    crash: Optional[bool] = None
    crash_id: Optional[str] = None
    crash_category: Optional[str] = None
    compile_success: Optional[bool] = None
    compile_error: Optional[str] = None
    execution_time_seconds: Optional[float] = None
    mutation_count: Optional[int] = None
    total_packets: Optional[int] = None
    timestamp: Optional[str] = None


class SweepProgress(BaseModel):
    timestamp: str
    tests_completed: Optional[int] = None
    tests_total: Optional[int] = None
    tests_remaining: Optional[int] = None
    crashes_found: Optional[int] = None
    unique_crash_ids: Optional[int] = None
    elapsed_seconds: Optional[float] = None
    avg_seconds_per_test: Optional[float] = None
    eta_seconds: Optional[float] = None
    eta_hours: Optional[float] = None
    status: Optional[str] = None


class EvaluationRow(BaseModel):
    run_id: str
    version: str
    evaluated_at: float  # epoch seconds
    session_id: Optional[str] = None
    model: Optional[str] = None
    device: Optional[str] = None
    protocol: Optional[str] = None
    max_turns: Optional[int] = None
    actual_turns: Optional[int] = None
    rq_max_score: Optional[int] = None
    rq_max_level: Optional[str] = None
    rq_mean_score: Optional[float] = None
    publicly_known_crashes: Optional[int] = None
    non_publicly_known_crashes: Optional[int] = None
    fully_novel_crashes: Optional[int] = None
    total_crashes: Optional[int] = None
    total_input_tokens: Optional[int] = None
    total_output_tokens: Optional[int] = None
    unique_crashes: Optional[int] = None
    unique_novel: Optional[int] = None
    total_tests: Optional[int] = None
    time_to_first_crash_seconds: Optional[float] = None
    tests_till_first_crash: Optional[int] = None
    total_session_time_seconds: Optional[float] = None
    source_csv_path: Optional[str] = None
    eval_id: Optional[str] = None

    @field_validator("eval_id")
    @classmethod
    def _check_eval_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None or v == "":
            return None
        if not re.fullmatch(r"[0-9a-f]{32}", v):
            raise ValueError("eval_id must be 32 lowercase hex chars")
        return v


class BlobRecord(BaseModel):
    run_id: str
    kind: str
    path: str


# ─── Helpers ───────────────────────────────────────────────────────────────


def _upsert_host(cur, host_id: str) -> None:
    cur.execute(
        "INSERT INTO host (host_id, first_seen, last_seen) "
        "VALUES (%s, now(), now()) "
        "ON CONFLICT (host_id) DO UPDATE SET last_seen = now()",
        (host_id,),
    )


def _ensure_run_stub(cur, run_id: str, host_id: str) -> None:
    """Create a placeholder run row so child events can land before run_start."""
    cur.execute(
        "INSERT INTO run (run_id, host_id, status, ingested_at) "
        "VALUES (%s, %s, 'partial', now()) "
        "ON CONFLICT (run_id) DO NOTHING",
        (run_id, host_id),
    )


def _ensure_sweep_stub(cur, sweep_id: str, host_id: str) -> None:
    cur.execute(
        "INSERT INTO sweep (sweep_id, host_id, status, ingested_at) "
        "VALUES (%s, %s, 'partial', now()) "
        "ON CONFLICT (sweep_id) DO NOTHING",
        (sweep_id, host_id),
    )


def _validate_run_id(run_id: str) -> None:
    if not (len(run_id) == 8 and all(c in "0123456789abcdef" for c in run_id)):
        raise HTTPException(
            400, f"Invalid run_id: {run_id!r} (expected 8 lowercase hex chars)"
        )


def _validate_sweep_id(sweep_id: str) -> None:
    # sweep_ids are uuid4().hex[:8] — same charset as run_id.
    _validate_run_id(sweep_id)


def _validate_host_id(host_id: str) -> None:
    import re

    if not re.fullmatch(r"[A-Za-z0-9._-]+", host_id):
        raise HTTPException(400, f"Invalid host_id: {host_id!r}")


def _json(value: Any) -> str | None:
    """Serialize lists/dicts for jsonb columns."""
    if value is None:
        return None
    return json.dumps(value)


# ─── Path normalization ────────────────────────────────────────────────────
# Workers post their *own* filesystem path for app_log, runtime_log, and the
# two metric PNGs. Those paths are nonsense on the master (different repo
# root, different user). The dashboard's data_loader.parse_reasoning() opens
# them at request time, so without rewriting we render every live run with
# no reasoning blocks. `scripts/backfill_to_db.py` already had this logic
# (`_normalize_path_to_master`); centralize it here so live + backfill both
# go through the same rewrite.
#
# Strategy: replace the entire prefix with `<master_AGENT_PATH>/<root_subdir>/<host>/<basename>`.
# Files always live as flat siblings inside the host subdir
# (`logs/<host>/<run>_app_<ts>.log`, `runtime_logs/<host>/<run>_manifest.json`,
# etc.), so basename is sufficient.

# Master's own AGENT_PATH. Resolved at import via env (the dashboard
# systemd unit's EnvironmentFile sets it). Falls back to cwd, which the
# unit's WorkingDirectory= also sets — both should match.
_MASTER_AGENT_PATH = os.environ.get("AGENT_PATH", os.getcwd())

_PATH_FIELD_TO_ROOT = {
    "app_log_path": "logs",
    "runtime_log_path": "runtime_logs",
    "metrics_png_path": "runtime_logs",
    "resource_metrics_png_path": "runtime_logs",
}


def _normalize_path_for_master(
    value: Optional[str], host_id: str, root_subdir: str
) -> Optional[str]:
    """Rewrite a worker-local path to its master-local equivalent.

    Returns the input unchanged if it's empty, already lives under the
    master root, or is a `_legacy` host (flat layout — original path was
    already correct on the master). Otherwise replaces everything before
    the basename with `<AGENT_PATH>/<root_subdir>/<host_id>/`.
    """
    if not value or host_id == "_legacy":
        return value
    expected_prefix = os.path.join(_MASTER_AGENT_PATH, root_subdir, host_id) + os.sep
    if value.startswith(expected_prefix):
        return value
    return os.path.join(
        _MASTER_AGENT_PATH, root_subdir, host_id, os.path.basename(value.rstrip("/"))
    )


def _normalize_run_paths(body) -> dict[str, Optional[str]]:
    """Apply `_normalize_path_for_master` to every path field on a RunStart-
    or RunFinish-shaped body. Returns a dict of the rewritten values keyed
    by attribute name, suitable for splat into the SQL parameters."""
    return {
        field: _normalize_path_for_master(
            getattr(body, field, None), body.host_id, root
        )
        for field, root in _PATH_FIELD_TO_ROOT.items()
    }


# ─── Healthcheck ───────────────────────────────────────────────────────────


@router.get("/healthz")
def health():
    if not healthcheck():
        raise HTTPException(status_code=503, detail="DB unavailable")
    return {"ok": True}


# ─── Run endpoints ─────────────────────────────────────────────────────────


@router.post("/runs", dependencies=[Depends(_require_token)])
def post_run(body: RunStart):
    _validate_run_id(body.run_id)
    _validate_host_id(body.host_id)

    started_at = to_ts(body.timestamp) if body.timestamp else None
    paths = _normalize_run_paths(body)

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            _upsert_host(cur, body.host_id)
            cur.execute(
                """
                INSERT INTO run (
                    run_id, session_id, host_id, device, protocol, version, model, max_turns,
                    timestamp_str, started_at,
                    app_log_path, runtime_log_path, metrics_png_path, resource_metrics_png_path,
                    status, ingested_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s,
                    %s, %s,
                    %s, %s, %s, %s,
                    'started', now()
                )
                ON CONFLICT (run_id) DO UPDATE SET
                    session_id                  = EXCLUDED.session_id,
                    host_id                     = EXCLUDED.host_id,
                    device                      = EXCLUDED.device,
                    protocol                    = EXCLUDED.protocol,
                    version                     = EXCLUDED.version,
                    model                       = EXCLUDED.model,
                    max_turns                   = EXCLUDED.max_turns,
                    timestamp_str               = EXCLUDED.timestamp_str,
                    started_at                  = EXCLUDED.started_at,
                    app_log_path                = EXCLUDED.app_log_path,
                    runtime_log_path            = EXCLUDED.runtime_log_path,
                    metrics_png_path            = EXCLUDED.metrics_png_path,
                    resource_metrics_png_path   = EXCLUDED.resource_metrics_png_path,
                    status                      = CASE WHEN run.status = 'partial'
                                                       THEN 'started' ELSE run.status END
                """,
                (
                    body.run_id,
                    body.session_id,
                    body.host_id,
                    body.device,
                    body.protocol,
                    body.version,
                    body.model,
                    body.max_turns,
                    body.timestamp,
                    started_at,
                    paths["app_log_path"],
                    paths["runtime_log_path"],
                    paths["metrics_png_path"],
                    paths["resource_metrics_png_path"],
                ),
            )
        conn.commit()
    return {"ok": True}


@router.patch("/runs/{run_id}", dependencies=[Depends(_require_token)])
def patch_run(run_id: str, body: RunPatch):
    _validate_run_id(run_id)
    fields = body.present()
    if not fields:
        return {"ok": True, "updated": 0}

    if "ended_at" in fields:
        fields["ended_at"] = to_ts(fields["ended_at"])

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT host_id FROM run WHERE run_id = %s", (run_id,))
            existing = cur.fetchone()
            if existing is None:
                raise HTTPException(404, f"Unknown run_id: {run_id}")
            # If a PATCH ever includes path fields (run_finish doesn't today,
            # but the model accepts them), apply the same worker→master
            # normalization that POST /runs does. Looking up host_id from the
            # existing row keeps RunPatch ignorant of identity.
            host_id = existing["host_id"] if isinstance(existing, dict) else existing[0]
            for f, root in _PATH_FIELD_TO_ROOT.items():
                if f in fields:
                    fields[f] = _normalize_path_for_master(fields[f], host_id, root)
            sql, params = build_partial_update("run", ["run_id"], [run_id], fields)
            cur.execute(sql, params)
        conn.commit()
    return {"ok": True, "updated": len(fields)}


@router.delete("/runs/{run_id}", dependencies=[Depends(_require_token)])
def delete_run(run_id: str):
    _validate_run_id(run_id)
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM run_blob WHERE run_id = %s", (run_id,))
            cur.execute("DELETE FROM evaluation WHERE run_id = %s", (run_id,))
            cur.execute("DELETE FROM test WHERE run_id = %s", (run_id,))
            cur.execute("DELETE FROM resource_sample WHERE run_id = %s", (run_id,))
            cur.execute("DELETE FROM turn WHERE run_id = %s", (run_id,))
            cur.execute("DELETE FROM run WHERE run_id = %s", (run_id,))
        conn.commit()
    return {"ok": True}



@router.post("/runs/{run_id}/turns", dependencies=[Depends(_require_token)])
def post_turns(
    run_id: str,
    body: list[TurnRecord],
    host_id: str = Header(default="", alias="X-Host-Id"),
):
    _validate_run_id(run_id)
    if not body:
        return {"ok": True, "rows": 0}
    if not host_id:
        raise HTTPException(
            400, "X-Host-Id header required for child events (FK stub creation)"
        )
    _validate_host_id(host_id)

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            _upsert_host(cur, host_id)
            _ensure_run_stub(cur, run_id, host_id)
            for rec in body:
                cur.execute(
                    """
                    INSERT INTO turn (
                        run_id, turn, ts, tools_called, tool_call_count, tool_counts,
                        input_tokens, output_tokens,
                        cumulative_input_tokens, cumulative_output_tokens,
                        turn_crashes, turn_publicly_known, turn_non_publicly_known, turn_fully_novel,
                        cumulative_crashes, cumulative_publicly_known,
                        cumulative_non_publicly_known, cumulative_fully_novel,
                        session_unique_crashes, phase, error
                    ) VALUES (
                        %s, %s, %s, %s::jsonb, %s, %s::jsonb,
                        %s, %s,
                        %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s
                    )
                    ON CONFLICT (run_id, turn) DO UPDATE SET
                        ts                              = EXCLUDED.ts,
                        tools_called                    = EXCLUDED.tools_called,
                        tool_call_count                 = EXCLUDED.tool_call_count,
                        tool_counts                     = EXCLUDED.tool_counts,
                        input_tokens                    = EXCLUDED.input_tokens,
                        output_tokens                   = EXCLUDED.output_tokens,
                        cumulative_input_tokens         = EXCLUDED.cumulative_input_tokens,
                        cumulative_output_tokens        = EXCLUDED.cumulative_output_tokens,
                        turn_crashes                    = EXCLUDED.turn_crashes,
                        turn_publicly_known             = EXCLUDED.turn_publicly_known,
                        turn_non_publicly_known         = EXCLUDED.turn_non_publicly_known,
                        turn_fully_novel                = EXCLUDED.turn_fully_novel,
                        cumulative_crashes              = EXCLUDED.cumulative_crashes,
                        cumulative_publicly_known       = EXCLUDED.cumulative_publicly_known,
                        cumulative_non_publicly_known   = EXCLUDED.cumulative_non_publicly_known,
                        cumulative_fully_novel          = EXCLUDED.cumulative_fully_novel,
                        session_unique_crashes          = EXCLUDED.session_unique_crashes,
                        phase                           = EXCLUDED.phase,
                        error                           = EXCLUDED.error
                    """,
                    (
                        run_id,
                        rec.turn,
                        to_ts(rec.timestamp),
                        _json(rec.tools_called),
                        rec.tool_call_count,
                        _json(rec.tool_counts),
                        rec.input_tokens,
                        rec.output_tokens,
                        rec.cumulative_input_tokens,
                        rec.cumulative_output_tokens,
                        rec.turn_crashes,
                        rec.turn_publicly_known,
                        rec.turn_non_publicly_known,
                        rec.turn_fully_novel,
                        rec.cumulative_crashes,
                        rec.cumulative_publicly_known,
                        rec.cumulative_non_publicly_known,
                        rec.cumulative_fully_novel,
                        rec.session_unique_crashes,
                        rec.phase,
                        rec.error,
                    ),
                )
        conn.commit()
    return {"ok": True, "rows": len(body)}


@router.post("/runs/{run_id}/resources", dependencies=[Depends(_require_token)])
def post_resources(
    run_id: str,
    body: list[ResourceSample],
    host_id: str = Header(default="", alias="X-Host-Id"),
):
    _validate_run_id(run_id)
    if not body:
        return {"ok": True, "rows": 0}
    if not host_id:
        raise HTTPException(400, "X-Host-Id header required")
    _validate_host_id(host_id)

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            _upsert_host(cur, host_id)
            _ensure_run_stub(cur, run_id, host_id)
            for s in body:
                cur.execute(
                    """
                    INSERT INTO resource_sample (
                        run_id, ts, turn, cpu_percent, mem_rss_mb, mem_system_percent,
                        disk_read_mb, disk_write_mb, net_sent_mb, net_recv_mb,
                        event, metadata
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s::jsonb
                    )
                    ON CONFLICT (run_id, ts) DO UPDATE SET
                        turn                = EXCLUDED.turn,
                        cpu_percent         = EXCLUDED.cpu_percent,
                        mem_rss_mb          = EXCLUDED.mem_rss_mb,
                        mem_system_percent  = EXCLUDED.mem_system_percent,
                        disk_read_mb        = EXCLUDED.disk_read_mb,
                        disk_write_mb       = EXCLUDED.disk_write_mb,
                        net_sent_mb         = EXCLUDED.net_sent_mb,
                        net_recv_mb         = EXCLUDED.net_recv_mb,
                        event               = EXCLUDED.event,
                        metadata            = EXCLUDED.metadata
                    """,
                    (
                        run_id,
                        to_ts(s.ts),
                        s.turn,
                        s.cpu_percent,
                        s.mem_rss_mb,
                        s.mem_system_percent,
                        s.disk_read_mb,
                        s.disk_write_mb,
                        s.net_sent_mb,
                        s.net_recv_mb,
                        s.event,
                        _json(s.metadata),
                    ),
                )
        conn.commit()
    return {"ok": True, "rows": len(body)}


@router.post("/runs/{run_id}/tests", dependencies=[Depends(_require_token)])
def post_tests(
    run_id: str,
    body: list[TestRecord],
    host_id: str = Header(default="", alias="X-Host-Id"),
):
    _validate_run_id(run_id)
    if not body:
        return {"ok": True, "rows": 0}
    if not host_id:
        raise HTTPException(400, "X-Host-Id header required")
    _validate_host_id(host_id)

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            _upsert_host(cur, host_id)
            _ensure_run_stub(cur, run_id, host_id)
            for t in body:
                cur.execute(
                    """
                    INSERT INTO test (
                        run_id, test_id, session_id, exploit_name, exploit_code, exploit_hash,
                        fuzz_description, crash, crash_category, crash_id,
                        new_states, new_transitions, compile_success, execution_time_seconds,
                        mutation_count, mutation_parse_warnings, total_packets,
                        timestamp_str, ts
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s::jsonb, %s,
                        %s, %s
                    )
                    ON CONFLICT (run_id, test_id) DO UPDATE SET
                        session_id              = EXCLUDED.session_id,
                        exploit_name            = EXCLUDED.exploit_name,
                        exploit_code            = EXCLUDED.exploit_code,
                        exploit_hash            = EXCLUDED.exploit_hash,
                        fuzz_description        = EXCLUDED.fuzz_description,
                        crash                   = EXCLUDED.crash,
                        crash_category          = EXCLUDED.crash_category,
                        crash_id                = EXCLUDED.crash_id,
                        new_states              = EXCLUDED.new_states,
                        new_transitions         = EXCLUDED.new_transitions,
                        compile_success         = EXCLUDED.compile_success,
                        execution_time_seconds  = EXCLUDED.execution_time_seconds,
                        mutation_count          = EXCLUDED.mutation_count,
                        mutation_parse_warnings = EXCLUDED.mutation_parse_warnings,
                        total_packets           = EXCLUDED.total_packets,
                        timestamp_str           = EXCLUDED.timestamp_str,
                        ts                      = EXCLUDED.ts
                    """,
                    (
                        run_id,
                        str(t.test_id),
                        t.session_id,
                        t.exploit_name,
                        t.exploit_code,
                        t.exploit_hash,
                        t.fuzz_description,
                        t.crash,
                        t.crash_category,
                        t.crash_id,
                        t.new_states,
                        t.new_transitions,
                        t.compile_success,
                        t.execution_time_seconds,
                        t.mutation_count,
                        _json(t.mutation_parse_warnings),
                        t.total_packets,
                        t.timestamp,
                        to_ts(t.timestamp) if t.timestamp else None,
                    ),
                )
        conn.commit()
    return {"ok": True, "rows": len(body)}


# ─── Findings ──────────────────────────────────────────────────────────────


@router.post("/findings", dependencies=[Depends(_require_token)])
def post_findings(
    body: list[SessionFinding],
    session_id: str = Header(default="", alias="X-Session-Id"),
):
    """Session findings — keyed (session_id, finding_id). session_id arrives
    via the X-Session-Id header, sourced from the worker envelope (the JSONL
    record itself does not include session_id — see knowledge_base.py:160)."""
    if not body:
        return {"ok": True, "rows": 0}
    if not session_id:
        raise HTTPException(400, "X-Session-Id header required")

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            for f in body:
                cur.execute(
                    """
                    INSERT INTO session_finding (
                        session_id, finding_id, type, description, related_tests, tags,
                        source_url, dedup_key, timestamp_str, ts
                    ) VALUES (
                        %s, %s, %s, %s, %s::jsonb, %s::jsonb,
                        %s, %s, %s, %s
                    )
                    ON CONFLICT (session_id, finding_id) DO UPDATE SET
                        type            = EXCLUDED.type,
                        description     = EXCLUDED.description,
                        related_tests   = EXCLUDED.related_tests,
                        tags            = EXCLUDED.tags,
                        source_url      = EXCLUDED.source_url,
                        dedup_key       = EXCLUDED.dedup_key,
                        timestamp_str   = EXCLUDED.timestamp_str,
                        ts              = EXCLUDED.ts
                    """,
                    (
                        session_id,
                        f.finding_id,
                        f.type,
                        f.description,
                        _json(f.related_tests),
                        _json(f.tags),
                        f.source_url,
                        f.dedup_key,
                        f.timestamp,
                        to_ts(f.timestamp) if f.timestamp else None,
                    ),
                )
        conn.commit()
    return {"ok": True, "rows": len(body)}


@router.post("/global_findings", dependencies=[Depends(_require_token)])
def post_global_findings(body: list[GlobalFinding]):
    if not body:
        return {"ok": True, "rows": 0}
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            for f in body:
                cur.execute(
                    """
                    INSERT INTO global_finding (
                        dedup_key, description, tags, source_session, timestamp_str, ts
                    ) VALUES (
                        %s, %s, %s::jsonb, %s, %s, %s
                    )
                    ON CONFLICT (dedup_key) DO UPDATE SET
                        description     = EXCLUDED.description,
                        tags            = EXCLUDED.tags,
                        source_session  = EXCLUDED.source_session,
                        timestamp_str   = EXCLUDED.timestamp_str,
                        ts              = EXCLUDED.ts
                    """,
                    (
                        f.dedup_key,
                        f.description,
                        _json(f.tags),
                        f.source_session,
                        f.timestamp,
                        to_ts(f.timestamp) if f.timestamp else None,
                    ),
                )
        conn.commit()
    return {"ok": True, "rows": len(body)}


@router.post("/strategy", dependencies=[Depends(_require_token)])
def post_strategy(body: SessionStrategy):
    """Strategy markdown text — KnowledgeBase.update_strategy() rewrites the
    whole file each call, so the table holds the latest version."""
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            if body.host_id:
                _validate_host_id(body.host_id)
                _upsert_host(cur, body.host_id)
            cur.execute(
                """
                INSERT INTO session_strategy (session_id, host_id, text, updated_at)
                VALUES (%s, %s, %s, now())
                ON CONFLICT (session_id) DO UPDATE SET
                    host_id     = EXCLUDED.host_id,
                    text        = EXCLUDED.text,
                    updated_at  = now()
                """,
                (body.session_id, body.host_id, body.text),
            )
        conn.commit()
    return {"ok": True}


# ─── Sweeps ────────────────────────────────────────────────────────────────


@router.post("/sweeps", dependencies=[Depends(_require_token)])
def post_sweep(body: SweepStart):
    _validate_sweep_id(body.sweep_id)
    _validate_host_id(body.host_id)
    if body.retry_of:
        _validate_sweep_id(body.retry_of)

    started_at = to_ts(body.start_time) if body.start_time else None
    offset_range = None
    if body.offset_range and len(body.offset_range) == 2:
        offset_range = f"[{body.offset_range[0]},{body.offset_range[1]})"

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            _upsert_host(cur, body.host_id)
            if body.retry_of:
                _ensure_sweep_stub(cur, body.retry_of, body.host_id)
            cur.execute(
                """
                INSERT INTO sweep (
                    sweep_id, host_id, device, protocol, profile, filters,
                    offset_range, offsets_per_filter, offset_strategy,
                    "values", values_hex, total_combinations, exploit_timeout,
                    retry_of, retry_depth,
                    start_time_str, started_at, status, ingested_at
                ) VALUES (
                    %s, %s, %s, %s, %s, %s::jsonb,
                    %s, %s, %s,
                    %s::jsonb, %s::jsonb, %s, %s,
                    %s, %s,
                    %s, %s, 'started', now()
                )
                ON CONFLICT (sweep_id) DO UPDATE SET
                    host_id             = EXCLUDED.host_id,
                    device              = EXCLUDED.device,
                    protocol            = EXCLUDED.protocol,
                    profile             = EXCLUDED.profile,
                    filters             = EXCLUDED.filters,
                    offset_range        = EXCLUDED.offset_range,
                    offsets_per_filter  = EXCLUDED.offsets_per_filter,
                    offset_strategy     = EXCLUDED.offset_strategy,
                    "values"            = EXCLUDED."values",
                    values_hex          = EXCLUDED.values_hex,
                    total_combinations  = EXCLUDED.total_combinations,
                    exploit_timeout     = EXCLUDED.exploit_timeout,
                    retry_of            = EXCLUDED.retry_of,
                    retry_depth         = EXCLUDED.retry_depth,
                    start_time_str      = EXCLUDED.start_time_str,
                    started_at          = EXCLUDED.started_at,
                    status              = CASE WHEN sweep.status = 'partial'
                                               THEN 'started' ELSE sweep.status END
                """,
                (
                    body.sweep_id,
                    body.host_id,
                    body.device,
                    body.protocol,
                    body.profile,
                    _json(body.filters),
                    offset_range,
                    body.offsets_per_filter,
                    body.offset_strategy,
                    _json(body.values),
                    _json(body.values_hex),
                    body.total_combinations,
                    body.exploit_timeout,
                    body.retry_of,
                    body.retry_depth,
                    body.start_time,
                    started_at,
                ),
            )
        conn.commit()
    return {"ok": True}


@router.patch("/sweeps/{sweep_id}", dependencies=[Depends(_require_token)])
def patch_sweep(sweep_id: str, body: SweepPatch):
    _validate_sweep_id(sweep_id)
    fields = body.present()
    if not fields:
        return {"ok": True, "updated": 0}
    if "ended_at" in fields:
        fields["ended_at"] = to_ts(fields["ended_at"])

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 FROM sweep WHERE sweep_id = %s", (sweep_id,))
            if cur.fetchone() is None:
                raise HTTPException(404, f"Unknown sweep_id: {sweep_id}")
            sql, params = build_partial_update(
                "sweep", ["sweep_id"], [sweep_id], fields
            )
            cur.execute(sql, params)
        conn.commit()
    return {"ok": True, "updated": len(fields)}


@router.post("/sweeps/{sweep_id}/tests", dependencies=[Depends(_require_token)])
def post_sweep_tests(
    sweep_id: str,
    body: list[SweepTest],
    host_id: str = Header(default="", alias="X-Host-Id"),
):
    _validate_sweep_id(sweep_id)
    if not body:
        return {"ok": True, "rows": 0}
    if not host_id:
        raise HTTPException(400, "X-Host-Id header required")
    _validate_host_id(host_id)

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            _upsert_host(cur, host_id)
            _ensure_sweep_stub(cur, sweep_id, host_id)
            for t in body:
                cur.execute(
                    """
                    INSERT INTO sweep_test (
                        sweep_id, test_num, filter, "offset", value, value_hex,
                        crash, crash_id, crash_category,
                        compile_success, compile_error, execution_time_seconds,
                        mutation_count, total_packets,
                        timestamp_str, ts
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s,
                        %s, %s, %s,
                        %s, %s, %s,
                        %s, %s,
                        %s, %s
                    )
                    ON CONFLICT (sweep_id, test_num) DO UPDATE SET
                        filter                  = EXCLUDED.filter,
                        "offset"                = EXCLUDED."offset",
                        value                   = EXCLUDED.value,
                        value_hex               = EXCLUDED.value_hex,
                        crash                   = EXCLUDED.crash,
                        crash_id                = EXCLUDED.crash_id,
                        crash_category          = EXCLUDED.crash_category,
                        compile_success         = EXCLUDED.compile_success,
                        compile_error           = EXCLUDED.compile_error,
                        execution_time_seconds  = EXCLUDED.execution_time_seconds,
                        mutation_count          = EXCLUDED.mutation_count,
                        total_packets           = EXCLUDED.total_packets,
                        timestamp_str           = EXCLUDED.timestamp_str,
                        ts                      = EXCLUDED.ts
                    """,
                    (
                        sweep_id,
                        t.test_num,
                        t.filter,
                        t.offset,
                        t.value,
                        t.value_hex,
                        t.crash,
                        t.crash_id,
                        t.crash_category,
                        t.compile_success,
                        t.compile_error,
                        t.execution_time_seconds,
                        t.mutation_count,
                        t.total_packets,
                        t.timestamp,
                        to_ts(t.timestamp) if t.timestamp else None,
                    ),
                )
        conn.commit()
    return {"ok": True, "rows": len(body)}


@router.post("/sweeps/{sweep_id}/progress", dependencies=[Depends(_require_token)])
def post_sweep_progress(
    sweep_id: str,
    body: list[SweepProgress],
    host_id: str = Header(default="", alias="X-Host-Id"),
):
    _validate_sweep_id(sweep_id)
    if not body:
        return {"ok": True, "rows": 0}
    if not host_id:
        raise HTTPException(400, "X-Host-Id header required")
    _validate_host_id(host_id)

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            _upsert_host(cur, host_id)
            _ensure_sweep_stub(cur, sweep_id, host_id)
            for p in body:
                ts = to_ts(p.timestamp)
                cur.execute(
                    """
                    INSERT INTO sweep_progress (
                        sweep_id, ts, timestamp_str, tests_completed, tests_total,
                        tests_remaining, crashes_found, unique_crash_ids,
                        elapsed_seconds, avg_seconds_per_test, eta_seconds, eta_hours, status
                    ) VALUES (
                        %s, %s, %s, %s, %s,
                        %s, %s, %s,
                        %s, %s, %s, %s, %s
                    )
                    ON CONFLICT (sweep_id, ts) DO UPDATE SET
                        timestamp_str           = EXCLUDED.timestamp_str,
                        tests_completed         = EXCLUDED.tests_completed,
                        tests_total             = EXCLUDED.tests_total,
                        tests_remaining         = EXCLUDED.tests_remaining,
                        crashes_found           = EXCLUDED.crashes_found,
                        unique_crash_ids        = EXCLUDED.unique_crash_ids,
                        elapsed_seconds         = EXCLUDED.elapsed_seconds,
                        avg_seconds_per_test    = EXCLUDED.avg_seconds_per_test,
                        eta_seconds             = EXCLUDED.eta_seconds,
                        eta_hours               = EXCLUDED.eta_hours,
                        status                  = EXCLUDED.status
                    """,
                    (
                        sweep_id,
                        ts,
                        p.timestamp,
                        p.tests_completed,
                        p.tests_total,
                        p.tests_remaining,
                        p.crashes_found,
                        p.unique_crash_ids,
                        p.elapsed_seconds,
                        p.avg_seconds_per_test,
                        p.eta_seconds,
                        p.eta_hours,
                        p.status,
                    ),
                )
        conn.commit()
    return {"ok": True, "rows": len(body)}


# ─── Evaluation ────────────────────────────────────────────────────────────


@router.post("/evaluations", dependencies=[Depends(_require_token)])
def post_evaluations(
    body: list[EvaluationRow], host_id: str = Header(default="", alias="X-Host-Id")
):
    if not body:
        return {"ok": True, "rows": 0}
    if not host_id:
        raise HTTPException(400, "X-Host-Id header required for FK stub creation")
    _validate_host_id(host_id)

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            _upsert_host(cur, host_id)
            for r in body:
                _validate_run_id(r.run_id)
                _ensure_run_stub(cur, r.run_id, host_id)
                cur.execute(
                    """
                    INSERT INTO evaluation (
                        run_id, version, evaluated_at, session_id, model, device, protocol, max_turns,
                        actual_turns, rq_max_score, rq_max_level, rq_mean_score,
                        publicly_known_crashes, non_publicly_known_crashes, fully_novel_crashes,
                        total_crashes, total_input_tokens, total_output_tokens,
                        unique_crashes, unique_novel, total_tests, time_to_first_crash_seconds,
                        tests_till_first_crash, total_session_time_seconds,
                        source_csv_path, eval_id
                    ) VALUES (
                        %s, %s, %s, %s, %s, %s, %s, %s,
                        %s, %s, %s, %s,
                        %s, %s, %s,
                        %s, %s, %s,
                        %s, %s, %s, %s, %s, %s,
                        %s, %s
                    )
                    ON CONFLICT (run_id) DO UPDATE SET
                        version                     = EXCLUDED.version,
                        evaluated_at                = EXCLUDED.evaluated_at,
                        session_id                  = EXCLUDED.session_id,
                        model                       = EXCLUDED.model,
                        device                      = EXCLUDED.device,
                        protocol                    = EXCLUDED.protocol,
                        max_turns                   = EXCLUDED.max_turns,
                        actual_turns                = EXCLUDED.actual_turns,
                        rq_max_score                = EXCLUDED.rq_max_score,
                        rq_max_level                = EXCLUDED.rq_max_level,
                        rq_mean_score               = EXCLUDED.rq_mean_score,
                        publicly_known_crashes      = EXCLUDED.publicly_known_crashes,
                        non_publicly_known_crashes  = EXCLUDED.non_publicly_known_crashes,
                        fully_novel_crashes         = EXCLUDED.fully_novel_crashes,
                        total_crashes               = EXCLUDED.total_crashes,
                        total_input_tokens          = EXCLUDED.total_input_tokens,
                        total_output_tokens         = EXCLUDED.total_output_tokens,
                        unique_crashes              = EXCLUDED.unique_crashes,
                        unique_novel                = EXCLUDED.unique_novel,
                        total_tests                 = EXCLUDED.total_tests,
                        time_to_first_crash_seconds = EXCLUDED.time_to_first_crash_seconds,
                        tests_till_first_crash      = EXCLUDED.tests_till_first_crash,
                        total_session_time_seconds  = EXCLUDED.total_session_time_seconds,
                        source_csv_path             = EXCLUDED.source_csv_path,
                        eval_id                     = COALESCE(EXCLUDED.eval_id, evaluation.eval_id)
                    """,
                    (
                        r.run_id,
                        r.version,
                        to_ts(r.evaluated_at),
                        r.session_id,
                        r.model,
                        r.device,
                        r.protocol,
                        r.max_turns,
                        r.actual_turns,
                        r.rq_max_score,
                        r.rq_max_level,
                        r.rq_mean_score,
                        r.publicly_known_crashes,
                        r.non_publicly_known_crashes,
                        r.fully_novel_crashes,
                        r.total_crashes,
                        r.total_input_tokens,
                        r.total_output_tokens,
                        r.unique_crashes,
                        r.unique_novel,
                        r.total_tests,
                        r.time_to_first_crash_seconds,
                        r.tests_till_first_crash,
                        r.total_session_time_seconds,
                        r.source_csv_path,
                        r.eval_id,
                    ),
                )
        conn.commit()
    return {"ok": True, "rows": len(body)}


# ─── Blobs ─────────────────────────────────────────────────────────────────


_BLOB_KINDS = {"app_log", "runtime_log", "metrics_png", "resource_metrics_png"}


@router.post("/blobs", dependencies=[Depends(_require_token)])
def post_blob(body: BlobRecord, host_id: str = Header(default="", alias="X-Host-Id")):
    _validate_run_id(body.run_id)
    if body.kind not in _BLOB_KINDS:
        raise HTTPException(
            400, f"Unknown blob kind: {body.kind} (allowed: {sorted(_BLOB_KINDS)})"
        )
    if not host_id:
        raise HTTPException(400, "X-Host-Id header required")
    _validate_host_id(host_id)

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            _upsert_host(cur, host_id)
            _ensure_run_stub(cur, body.run_id, host_id)
            cur.execute(
                """
                INSERT INTO run_blob (run_id, kind, path)
                VALUES (%s, %s, %s)
                ON CONFLICT (run_id, kind) DO UPDATE SET path = EXCLUDED.path
                """,
                (body.run_id, body.kind, body.path),
            )
            # Mirror the path onto the run row's denormalized column too,
            # so the dashboard does not need to JOIN run_blob for the
            # display-time path lookups.
            col_map = {
                "app_log": "app_log_path",
                "runtime_log": "runtime_log_path",
                "metrics_png": "metrics_png_path",
                "resource_metrics_png": "resource_metrics_png_path",
            }
            cur.execute(
                f"UPDATE run SET {col_map[body.kind]} = %s WHERE run_id = %s",
                (body.path, body.run_id),
            )
        conn.commit()
    return {"ok": True}
