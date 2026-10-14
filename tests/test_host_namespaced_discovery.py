"""Tests for host-namespaced discovery and field-aware manifest path normalization.

Workers stream their per-host subtrees (`runtime_logs/<host>/`,
`sweep_logs/<host>/`, `logs/<host>/`, `kb/<host>/`) to a master via rsync.
The master's dashboard discovery layer must (a) walk every host subdir and
(b) rewrite worker-side absolute paths inside synced manifests so files
resolve under the master's local trees.
"""

import json
import os
import sys

import pytest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(TESTS_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

# These tests exercise the host-namespaced filesystem discovery contract
# that lives in the file-backed loader (and in evals/resolve_run.py, which
# stays file-backed during the cutover). data_loader (SQL-backed) does not
# carry these helpers any more — they live in data_loader_files now.
from dashboard import data_loader_files as data_loader
from evals import resolve_run as rr

sweep_config = pytest.importorskip("sweep_scripts_202604.config")
sweep_plan = pytest.importorskip("sweep_scripts_202604.plan")


# ─────────────────────────────────────────────────────────────────────────
# Discovery: list_runs / list_sweeps walk host subdirs
# ─────────────────────────────────────────────────────────────────────────


def test_list_runs_walks_host_subdirs(tmp_path, monkeypatch):
    """Two manifests on two different hosts both surface in list_runs()."""
    monkeypatch.setattr("evals.resolve_run.RUNTIME_LOG_ROOT", str(tmp_path))

    for host, rid in [("host_a", "aaaa1111"), ("host_b", "bbbb2222")]:
        host_dir = tmp_path / host
        host_dir.mkdir()
        (host_dir / f"{rid}_manifest.json").write_text(
            json.dumps(
                {
                    "run_id": rid,
                    "timestamp": "20260316-152200",
                }
            )
        )

    runs = rr.list_runs()
    rids = sorted(r["run_id"] for r in runs)
    assert rids == ["aaaa1111", "bbbb2222"]


def test_list_sweeps_walks_host_subdirs(tmp_path, monkeypatch):
    """list_sweeps surfaces sweeps from every host subdir."""
    monkeypatch.setattr(data_loader, "SWEEP_LOG_ROOT", str(tmp_path))

    for host, sid in [("host_a", "sweep001"), ("host_b", "sweep002")]:
        d = tmp_path / host / sid
        d.mkdir(parents=True)
        (d / "manifest.json").write_text(
            json.dumps(
                {
                    "sweep_id": sid,
                    "modem": "mediatek",
                    "profile": "quick",
                    "total_combinations": 0,
                    "start_time": "2026-04-01T00:00:00",
                    "filters": [],
                    "values": [],
                }
            )
        )

    sweeps = data_loader.list_sweeps()
    sids = sorted(s["sweep_id"] for s in sweeps)
    assert sids == ["sweep001", "sweep002"]


# ─────────────────────────────────────────────────────────────────────────
# Retry chain crosses hosts
# ─────────────────────────────────────────────────────────────────────────


def test_retry_chain_across_hosts(tmp_path, monkeypatch):
    """Parent sweep on host_a, retry on host_b — find_retry_child still resolves."""
    monkeypatch.setattr(sweep_config, "SWEEP_LOG_ROOT", str(tmp_path))
    monkeypatch.setattr(sweep_plan, "SWEEP_LOG_ROOT", str(tmp_path))

    parent_id = "parentaa"
    child_id = "childbbb"

    parent_dir = tmp_path / "host_a" / parent_id
    parent_dir.mkdir(parents=True)
    (parent_dir / "manifest.json").write_text(
        json.dumps(
            {
                "sweep_id": parent_id,
                "modem": "mediatek",
                "profile": "quick",
            }
        )
    )

    child_dir = tmp_path / "host_b" / child_id
    child_dir.mkdir(parents=True)
    (child_dir / "manifest.json").write_text(
        json.dumps(
            {
                "sweep_id": child_id,
                "modem": "mediatek",
                "profile": "quick",
                "retry_of": parent_id,
                "retry_depth": 1,
            }
        )
    )

    found_child = sweep_plan.find_retry_child(parent_id)
    assert found_child == child_id
    assert sweep_plan.find_retry_chain(parent_id) == [child_id]


# ─────────────────────────────────────────────────────────────────────────
# Field-aware path normalization (runtime manifests)
# ─────────────────────────────────────────────────────────────────────────


def test_runtime_manifest_paths_normalized_to_per_root_per_host(tmp_path, monkeypatch):
    """A worker's manifest with /worker_root/... paths normalizes to per-root,
    per-host paths under the master's local tree.

    runtime_log/metrics/resources go under RUNTIME_LOG_ROOT/<host>;
    app_log goes under LOG_ROOT/<host>;
    kb_dir goes under KB_ROOT/<host>.
    """
    runtime_root = tmp_path / "runtime"
    log_root = tmp_path / "logs"
    kb_root = tmp_path / "kb"
    for d in (runtime_root, log_root, kb_root):
        (d / "ud710").mkdir(parents=True)

    monkeypatch.setattr("evals.resolve_run.RUNTIME_LOG_ROOT", str(runtime_root))
    monkeypatch.setattr("evals.resolve_run.LOG_ROOT", str(log_root))
    monkeypatch.setattr("evals.resolve_run.KB_ROOT", str(kb_root))

    run_id = "ab12cd34"
    session_id = f"{run_id}-rq1-v3-20260316-152200"

    # The manifest carries worker-side absolute paths (a totally different
    # filesystem layout than the master).
    manifest = {
        "run_id": run_id,
        "session_id": session_id,
        "timestamp": "20260316-152200",
        "model": "anthropic/claude-sonnet-4.6",
        "modem": "mediatek",
        "runtime_log": "/worker/.../runtime_logs/ab12cd34_run_20260316_152200.log",
        "metrics": "/worker/.../runtime_logs/agent_metrics_ab12cd34.jsonl",
        "resources": "/worker/.../runtime_logs/resources_ab12cd34.jsonl",
        "app_log": "/worker/.../logs/ab12cd34_app_20260316_152200.log",
        "kb_dir": f"/worker/.../kb/{session_id}",
    }
    manifest_path = runtime_root / "ud710" / f"{run_id}_manifest.json"
    manifest_path.write_text(json.dumps(manifest))

    # Create the actual files at the master-side normalized paths so we can
    # also assert load_run_data picks them up.
    (runtime_root / "ud710" / f"{run_id}_run_20260316_152200.log").write_text(
        "runtime log"
    )
    (runtime_root / "ud710" / f"agent_metrics_{run_id}.jsonl").write_text("")
    (runtime_root / "ud710" / f"resources_{run_id}.jsonl").write_text("")
    (log_root / "ud710" / f"{run_id}_app_20260316_152200.log").write_text("app log")
    (kb_root / "ud710" / session_id).mkdir()

    info = rr.resolve_run(run_id)

    # Each field resolves under the right root + host segment.
    assert info["runtime_log"] == str(
        runtime_root / "ud710" / f"{run_id}_run_20260316_152200.log"
    )
    assert info["metrics"] == str(
        runtime_root / "ud710" / f"agent_metrics_{run_id}.jsonl"
    )
    assert info["resources"] == str(
        runtime_root / "ud710" / f"resources_{run_id}.jsonl"
    )
    assert info["app_log"] == str(
        log_root / "ud710" / f"{run_id}_app_20260316_152200.log"
    )
    assert info["kb_dir"] == str(kb_root / "ud710" / session_id)

    # All resolved paths exist on disk (the actual fix, observed end-to-end).
    for f in ("runtime_log", "metrics", "resources", "app_log"):
        assert os.path.exists(info[f]), f"{f} does not exist after normalization"
    assert os.path.isdir(info["kb_dir"])


def test_runtime_flat_layout_paths_left_alone(tmp_path, monkeypatch):
    """Pre-migration flat layout: manifests at runtime_logs/<id>_manifest.json
    have no host segment, so embedded paths must NOT be rewritten — they're
    already correct for this host."""
    monkeypatch.setattr("evals.resolve_run.RUNTIME_LOG_ROOT", str(tmp_path))

    run_id = "deadbeef"
    metrics_real = tmp_path / f"agent_metrics_{run_id}.jsonl"
    metrics_real.write_text("")
    manifest = {
        "run_id": run_id,
        "metrics": str(metrics_real),
    }
    (tmp_path / f"{run_id}_manifest.json").write_text(json.dumps(manifest))

    info = rr.resolve_run(run_id)
    assert info["metrics"] == str(metrics_real)


# ─────────────────────────────────────────────────────────────────────────
# Field-aware path normalization (sweep manifests)
# ─────────────────────────────────────────────────────────────────────────


def test_sweep_manifest_results_path_resolves_to_manifest_dir(tmp_path, monkeypatch):
    """A sweep manifest with worker-side absolute results_path / progress_path
    is normalized to point next to the manifest after sync."""
    monkeypatch.setattr(data_loader, "SWEEP_LOG_ROOT", str(tmp_path))

    sid = "sweepXYZ"
    sweep_dir = tmp_path / "ud710" / sid
    sweep_dir.mkdir(parents=True)

    manifest = {
        "sweep_id": sid,
        "modem": "mediatek",
        "profile": "quick",
        "filters": ["nr-rrc.rrcSetup_element"],
        "values": [0x5B],
        "total_combinations": 1,
        "start_time": "2026-04-01T00:00:00",
        # Worker-side paths — would not exist on the master.
        "results_path": "/worker/.../sweep_logs/sweepXYZ/results.jsonl",
        "progress_path": "/worker/.../sweep_logs/sweepXYZ/progress.jsonl",
    }
    (sweep_dir / "manifest.json").write_text(json.dumps(manifest))

    # Real files live next to the manifest (where rsync put them).
    (sweep_dir / "results.jsonl").write_text(
        json.dumps(
            {
                "sweep_id": sid,
                "test_num": 1,
                "filter": "nr-rrc.rrcSetup_element",
                "offset": 0,
                "value": 0x5B,
                "crash": False,
                "crash_id": None,
                "compile_success": True,
                "execution_time_seconds": 1.0,
            }
        )
        + "\n"
    )
    (sweep_dir / "progress.jsonl").write_text(
        json.dumps(
            {
                "sweep_id": sid,
                "tests_completed": 1,
                "tests_total": 1,
                "status": "completed",
            }
        )
        + "\n"
    )

    data = data_loader.load_sweep_data(sid)
    assert data is not None
    assert len(data["results"]) == 1
    assert data["progress"]["tests_completed"] >= 1


# ─────────────────────────────────────────────────────────────────────────
# JSONL streaming-tear tolerance
# ─────────────────────────────────────────────────────────────────────────


def test_read_jsonl_drops_trailing_partial_line(tmp_path):
    """Streaming-tear case: rsync caught a file mid-append, so the last line
    is half-written. read_jsonl returns the complete records and silently
    drops the partial line."""
    p = tmp_path / "stream.jsonl"
    p.write_text(
        json.dumps({"i": 1})
        + "\n"
        + json.dumps({"i": 2})
        + "\n"
        + '{"i": 3, "partial":'  # truncated mid-write — no trailing newline
    )
    records = data_loader.read_jsonl(str(p))
    assert records == [{"i": 1}, {"i": 2}]


def test_read_jsonl_silently_skips_mid_file_corruption(tmp_path):
    """Disclosure test: read_jsonl ALSO drops malformed lines in the middle of
    the file, not just the trailing partial. This is the documented behavior —
    if you need stricter trailing-only tolerance, add a new helper rather
    than tightening this one. This test pins the contract so a future change
    can't silently broaden or narrow it."""
    p = tmp_path / "corrupt.jsonl"
    p.write_text(
        json.dumps({"i": 1}) + "\n" + "NOT VALID JSON\n" + json.dumps({"i": 3}) + "\n"
    )
    records = data_loader.read_jsonl(str(p))
    assert records == [{"i": 1}, {"i": 3}]


# ─────────────────────────────────────────────────────────────────────────
# HOST_ID validation
# ─────────────────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "bad_id",
    [
        "../escape",
        "foo/bar",
        "name with space",
        "$(rm -rf /)",
        "host;id",
    ],
)
def test_host_id_rejects_shell_hostile_values(bad_id, monkeypatch):
    """Set AGENT_HOST_ID to an unsafe value and confirm constants.py refuses it.

    HOST_ID flows into filesystem paths and rsync destinations; injection
    here would compromise both. The validation regex is `[A-Za-z0-9._-]+`.
    Empty AGENT_HOST_ID falls through to socket.gethostname() — that's the
    documented behavior, not a validation case.
    """
    import importlib
    import constants

    monkeypatch.setenv("AGENT_HOST_ID", bad_id)
    with pytest.raises(ValueError, match="Invalid AGENT_HOST_ID"):
        importlib.reload(constants)
    # Reload with a sane value to leave the module in a valid state for
    # subsequent tests.
    monkeypatch.delenv("AGENT_HOST_ID", raising=False)
    importlib.reload(constants)
