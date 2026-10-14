"""Tests for evals/resolve_run.py — run_id resolver utility."""

import json
import os
import sys


TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(TESTS_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from evals.resolve_run import resolve_run, resolve_session_to_run_id, list_runs


def test_resolve_run_from_manifest(tmp_path, monkeypatch):
    """resolve_run() returns manifest contents when manifest exists under a host subdir."""
    monkeypatch.setattr("evals.resolve_run.RUNTIME_LOG_ROOT", str(tmp_path))

    run_id = "ab12cd34"
    host_dir = tmp_path / "host_a"
    host_dir.mkdir()
    manifest = {
        "run_id": run_id,
        "session_id": f"{run_id}-rq1-v1-20260316-152200",
        "timestamp": "20260316-152200",
        "metrics": str(host_dir / f"agent_metrics_{run_id}.jsonl"),
        "kb_dir": str(host_dir / f"{run_id}-rq1-v1-20260316-152200"),
    }
    manifest_path = host_dir / f"{run_id}_manifest.json"
    manifest_path.write_text(json.dumps(manifest))

    result = resolve_run(run_id)
    assert result["run_id"] == run_id
    assert result["session_id"] == f"{run_id}-rq1-v1-20260316-152200"


def test_resolve_run_fallback_glob(tmp_path, monkeypatch):
    """resolve_run() finds artifacts via glob when no manifest exists, walking host subdirs."""
    runtime_root = tmp_path / "runtime"
    log_root = tmp_path / "logs"
    kb_root = tmp_path / "kb"
    for d in (runtime_root, log_root, kb_root):
        (d / "host_a").mkdir(parents=True)

    monkeypatch.setattr("evals.resolve_run.RUNTIME_LOG_ROOT", str(runtime_root))
    monkeypatch.setattr("evals.resolve_run.LOG_ROOT", str(log_root))
    monkeypatch.setattr("evals.resolve_run.KB_ROOT", str(kb_root))

    run_id = "ff00ff00"

    # Create artifacts under host_a
    (runtime_root / "host_a" / f"{run_id}_run_20260316_152200.log").write_text(
        "log content"
    )
    (log_root / "host_a" / f"{run_id}_app_20260316_152200.log").write_text("app log")
    (runtime_root / "host_a" / f"agent_metrics_{run_id}.jsonl").write_text("")
    kb_dir = kb_root / "host_a" / f"{run_id}-rq1-v1-20260316-152200"
    kb_dir.mkdir()

    result = resolve_run(run_id)
    assert result["run_id"] == run_id
    assert "runtime_log" in result
    assert "app_log" in result
    assert "kb_dir" in result
    assert result["session_id"] == f"{run_id}-rq1-v1-20260316-152200"


def test_resolve_session_to_run_id():
    """run_id is extracted from session_id prefix."""
    assert resolve_session_to_run_id("dd7a0f0a-rq1-v1-20260316-152200") == "dd7a0f0a"
    assert resolve_session_to_run_id("dd7a0f0a-coldstart-20260316-152200") == "dd7a0f0a"
    assert resolve_session_to_run_id("dd7a0f0a") == "dd7a0f0a"
    assert resolve_session_to_run_id("short") is None  # not 8 hex chars
    assert resolve_session_to_run_id("notahexv-something") is None  # not hex


def test_list_runs(tmp_path, monkeypatch):
    """list_runs() returns manifests across host subdirs, sorted."""
    monkeypatch.setattr("evals.resolve_run.RUNTIME_LOG_ROOT", str(tmp_path))

    host_a = tmp_path / "host_a"
    host_b = tmp_path / "host_b"
    host_a.mkdir()
    host_b.mkdir()

    for rid, host in [("aaaa0001", host_a), ("bbbb0002", host_b)]:
        manifest = {"run_id": rid, "timestamp": "20260316-152200"}
        (host / f"{rid}_manifest.json").write_text(json.dumps(manifest))

    runs = list_runs()
    assert len(runs) == 2
    rids = [r["run_id"] for r in runs]
    assert "aaaa0001" in rids
    assert "bbbb0002" in rids
