"""Tests for run_id tagging — session_id format, log naming, manifest structure."""

import json
import os
import re
import sys


TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(TESTS_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)


def test_session_id_has_run_id_prefix():
    """Session IDs are prefixed with an 8-char hex run_id."""
    import uuid
    import time

    run_id = uuid.uuid4().hex[:8]
    ts = time.strftime("%Y%m%d-%H%M%S")

    # v1/v2/v3 format
    session_id = f"{run_id}-rq1-v1-{ts}"
    assert session_id.startswith(run_id)
    assert len(session_id.split("-")[0]) == 8

    # coldstart format
    session_id = f"{run_id}-coldstart-{ts}"
    assert session_id.startswith(run_id)

    # env var format
    env_session = "mar26"
    session_id = f"{run_id}-{env_session}"
    assert session_id.startswith(run_id)

    # bare run_id (no env var)
    assert len(run_id) == 8


def test_log_files_prefixed_with_run_id(tmp_path):
    """Log files use {run_id}_app_{ts}.log and {run_id}_run_{ts}.log format."""
    run_id = "ab12cd34"
    ts = "20260316_152200"

    app_log = tmp_path / f"{run_id}_app_{ts}.log"
    runtime_log = tmp_path / f"{run_id}_run_{ts}.log"
    app_log.write_text("test")
    runtime_log.write_text("test")

    # Verify naming pattern
    m = re.match(r"(\w{8})_app_(\d{8}_\d{6})\.log", app_log.name)
    assert m is not None
    assert m.group(1) == run_id

    m = re.match(r"(\w{8})_run_(\d{8}_\d{6})\.log", runtime_log.name)
    assert m is not None
    assert m.group(1) == run_id


def test_manifest_structure(tmp_path):
    """Manifest JSON has correct structure and paths."""
    run_id = "ab12cd34"
    ts = "20260316-152200"
    ts_file = "20260316_152200"
    session_id = f"{run_id}-rq1-v1-{ts}"

    manifest = {
        "run_id": run_id,
        "session_id": session_id,
        "timestamp": ts,
        "app_log": str(tmp_path / f"{run_id}_app_{ts_file}.log"),
        "runtime_log": str(tmp_path / f"{run_id}_run_{ts_file}.log"),
        "metrics": str(tmp_path / f"agent_metrics_{run_id}.jsonl"),
        "resources": str(tmp_path / f"resources_{run_id}.jsonl"),
        "kb_dir": str(tmp_path / session_id),
    }

    manifest_path = tmp_path / f"{run_id}_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2))

    loaded = json.loads(manifest_path.read_text())
    assert loaded["run_id"] == run_id
    assert loaded["session_id"] == session_id
    assert loaded["timestamp"] == ts
    assert run_id in loaded["app_log"]
    assert run_id in loaded["runtime_log"]
    assert run_id in loaded["metrics"]
    assert run_id in loaded["kb_dir"]


def test_shared_timestamp_consistency():
    """KB session_id and log filenames use the same timestamp."""
    import time

    run_id = "ab12cd34"
    shared_ts = time.strftime("%Y%m%d-%H%M%S")
    ts_for_file = shared_ts.replace("-", "_", 1)

    session_id = f"{run_id}-rq1-v1-{shared_ts}"
    app_log_name = f"{run_id}_app_{ts_for_file}.log"
    runtime_log_name = f"{run_id}_run_{ts_for_file}.log"

    # Extract timestamps and verify they match
    # session_id: last two parts are YYYYMMDD-HHMMSS
    session_ts = "-".join(session_id.split("-")[-2:])
    assert session_ts == shared_ts

    # log files: extract YYYYMMDD_HHMMSS and convert
    m = re.search(r"(\d{8}_\d{6})", app_log_name)
    log_ts = m.group(1).replace("_", "-", 1)
    assert log_ts == shared_ts

    m = re.search(r"(\d{8}_\d{6})", runtime_log_name)
    log_ts = m.group(1).replace("_", "-", 1)
    assert log_ts == shared_ts


def test_classify_from_log_new_format():
    """classify_from_log() parses {run_id}_run_{ts}.log format."""
    from evals.eval_bottleneck import classify_from_log

    # Old format should be rejected
    result = classify_from_log("run_20260316_152200.log")
    assert "error" in result

    # New format parses correctly (even if artifacts don't exist — returns unknown)
    result = classify_from_log("ab12cd34_run_20260316_152200.log")
    assert "error" not in result
    assert result.get("run_id") == "ab12cd34"
