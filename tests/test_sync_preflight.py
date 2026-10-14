"""Tests for the sync_preflight policy.

Policy B: a worker that *looks* like it should be streaming but isn't
fails at startup; master/dev/CI opts out via AGENT_NO_SYNC=1.

These tests run everywhere (no real network) — they monkeypatch HOME,
the env var, and subprocess.run.
"""

import os
import subprocess
import sys

import pytest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(TESTS_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

import sync_preflight  # noqa: E402


@pytest.fixture
def isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv(sync_preflight.OPT_OUT_VAR, raising=False)
    monkeypatch.setattr(
        sync_preflight,
        "ENV_FILE",
        os.path.join(str(tmp_path), ".agentic-fuzz-sync.env"),
    )
    return tmp_path


def _write_env(home, **overrides):
    keys = {
        "AGENT_MASTER": "debian@10.0.0.1",
        "AGENT_MASTER_PATH": "/srv/agentic-fuzz",
        "AGENT_HOST_ID": "test-host",
        "AGENT_LOCAL_PATH": str(home),
        "AGENT_INGEST_URL": "http://10.0.0.1:8000",
        "AGENT_INGEST_TOKEN": "test-token",
    }
    keys.update(overrides)
    with open(os.path.join(str(home), ".agentic-fuzz-sync.env"), "w") as f:
        for k, v in keys.items():
            f.write(f"{k}={v}\n")


def _stub_healthz_ok(monkeypatch, status=200, body='{"ok":true}'):
    def fake(url, timeout=sync_preflight.HEALTHZ_TIMEOUT):
        return status, body

    monkeypatch.setattr(sync_preflight, "_probe_healthz", fake)


def _stub_ssh_ok(monkeypatch):
    def fake_run(*a, **kw):
        return subprocess.CompletedProcess(a, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(sync_preflight.subprocess, "run", fake_run)


def test_opt_out_returns_silently(isolated_home, monkeypatch, capsys):
    monkeypatch.setenv(sync_preflight.OPT_OUT_VAR, "1")
    sync_preflight.check_streaming_or_exit()  # must not raise / exit


def test_missing_env_file_exits(isolated_home, capsys):
    with pytest.raises(SystemExit) as exc:
        sync_preflight.check_streaming_or_exit()
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "not found" in err
    assert sync_preflight.OPT_OUT_VAR in err


def test_env_missing_keys_exits(isolated_home, capsys):
    _write_env(isolated_home, AGENT_MASTER="")
    with pytest.raises(SystemExit) as exc:
        sync_preflight.check_streaming_or_exit()
    assert exc.value.code == 2
    assert "AGENT_MASTER" in capsys.readouterr().err


def test_ssh_failure_exits(isolated_home, monkeypatch, capsys):
    _write_env(isolated_home)

    def fake_run(*a, **kw):
        return subprocess.CompletedProcess(
            a, returncode=255, stdout="", stderr="ssh: connection refused"
        )

    monkeypatch.setattr(sync_preflight.subprocess, "run", fake_run)

    with pytest.raises(SystemExit) as exc:
        sync_preflight.check_streaming_or_exit()
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "connection refused" in err
    assert "ssh debian@10.0.0.1 returned 255" in err


def test_happy_path_returns(isolated_home, monkeypatch):
    _write_env(isolated_home)
    _stub_ssh_ok(monkeypatch)
    _stub_healthz_ok(monkeypatch)

    sync_preflight.check_streaming_or_exit()  # no raise / exit


# ─── Postgres ingest API: keys + healthz reachability ──────────────────────
#
# Workers stream structured data through the ingest API on the master, not
# rsync. If AGENT_INGEST_URL or AGENT_INGEST_TOKEN are missing from the
# worker's env file, or the master's /healthz endpoint is unreachable,
# preflight must hard-exit instead of silently producing local-only data.


def test_env_missing_ingest_url_exits(isolated_home, monkeypatch, capsys):
    _write_env(isolated_home, AGENT_INGEST_URL="")
    _stub_ssh_ok(monkeypatch)
    _stub_healthz_ok(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        sync_preflight.check_streaming_or_exit()
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "AGENT_INGEST_URL" in err


def test_env_missing_ingest_token_exits(isolated_home, monkeypatch, capsys):
    _write_env(isolated_home, AGENT_INGEST_TOKEN="")
    _stub_ssh_ok(monkeypatch)
    _stub_healthz_ok(monkeypatch)

    with pytest.raises(SystemExit) as exc:
        sync_preflight.check_streaming_or_exit()
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "AGENT_INGEST_TOKEN" in err


def test_healthz_unreachable_exits(isolated_home, monkeypatch, capsys):
    """Mirrors `curl -sf http://<master>:8000/healthz` failing — preflight
    must surface that as exit 2, not let the run start anyway."""
    _write_env(isolated_home, AGENT_INGEST_URL="http://192.0.2.10:8000")
    _stub_ssh_ok(monkeypatch)

    def fake_probe(url, timeout=sync_preflight.HEALTHZ_TIMEOUT):
        raise ConnectionRefusedError("Connection refused")

    monkeypatch.setattr(sync_preflight, "_probe_healthz", fake_probe)

    with pytest.raises(SystemExit) as exc:
        sync_preflight.check_streaming_or_exit()
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "192.0.2.10:8000" in err
    assert "Connection refused" in err


def test_healthz_non_200_exits(isolated_home, monkeypatch, capsys):
    _write_env(isolated_home, AGENT_INGEST_URL="http://192.0.2.10:8000")
    _stub_ssh_ok(monkeypatch)
    _stub_healthz_ok(monkeypatch, status=503, body="upstream down")

    with pytest.raises(SystemExit) as exc:
        sync_preflight.check_streaming_or_exit()
    assert exc.value.code == 2
    err = capsys.readouterr().err
    assert "HTTP 503" in err
    assert "/healthz" in err


# ─── End-of-run hook (trigger_master_deploy_or_exit) ───────────────────────
#
# After the Postgres cutover, the trigger is a no-op stub: the static
# Cloudflare Pages deploy was retired when the master moved to a live
# DB-backed dashboard. The signature, call sites, and exports are kept
# so the cleanup PR can drop them in one coordinated change.


@pytest.fixture
def fresh_env(monkeypatch):
    monkeypatch.delenv(sync_preflight.OPT_OUT_VAR, raising=False)


def test_end_of_run_is_noop(fresh_env, monkeypatch, tmp_path):
    """Stub must not invoke any subprocess and must return silently."""
    called = {"n": 0}

    def fake_run(*a, **kw):
        called["n"] += 1
        return subprocess.CompletedProcess(a, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(sync_preflight.subprocess, "run", fake_run)

    sync_preflight.trigger_master_deploy_or_exit(agent_path=str(tmp_path))
    assert called["n"] == 0


def test_end_of_run_noop_with_opt_out(fresh_env, monkeypatch, tmp_path):
    """Opt-out remains a no-op too — backward-compatible with old callers."""
    monkeypatch.setenv(sync_preflight.OPT_OUT_VAR, "1")
    called = {"n": 0}

    def fake_run(*a, **kw):
        called["n"] += 1
        return subprocess.CompletedProcess(a, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(sync_preflight.subprocess, "run", fake_run)

    sync_preflight.trigger_master_deploy_or_exit(agent_path=str(tmp_path))
    assert called["n"] == 0


def test_end_of_run_uses_logger_when_provided(fresh_env, tmp_path):
    """Logger path is what production uses — confirm info routing on the stub."""

    class FakeLogger:
        def __init__(self):
            self.info_calls = []
            self.error_calls = []

        def info(self, msg):
            self.info_calls.append(msg)

        def error(self, msg):
            self.error_calls.append(msg)

        def warning(self, msg):
            pass

    log = FakeLogger()
    sync_preflight.trigger_master_deploy_or_exit(log, agent_path=str(tmp_path))
    assert any("no-op" in m for m in log.info_calls)
    assert log.error_calls == []


# ─── Integration: subprocess invocation propagates exit code ───────────────
# Catches regressions where sys.exit() inside check_streaming_or_exit() gets
# swallowed by a bare `except:` somewhere up the stack.


def test_check_streaming_propagates_exit_code_via_subprocess(tmp_path):
    """End-to-end: a subprocess that imports sync_preflight and calls
    check_streaming_or_exit() with no env file must exit 2."""
    env = os.environ.copy()
    env["HOME"] = str(tmp_path)
    env.pop(sync_preflight.OPT_OUT_VAR, None)
    env["PYTHONPATH"] = AGENT_DIR + ":" + env.get("PYTHONPATH", "")
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sync_preflight; sync_preflight.check_streaming_or_exit()",
        ],
        env=env,
        capture_output=True,
        text=True,
        timeout=15,
    )
    assert proc.returncode == 2
    assert "not found" in proc.stderr


# ─── Tests for run_preflight_checks ──────────────────────────────────────────

from unittest.mock import MagicMock


def test_run_preflight_checks_happy_path(isolated_home, monkeypatch):
    _write_env(isolated_home)
    _stub_ssh_ok(monkeypatch)
    _stub_healthz_ok(monkeypatch)

    requests_sent = []

    class FakeResponse:
        def __init__(self, status):
            self.status = status
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    def fake_urlopen(req, *args, **kwargs):
        requests_sent.append(req)
        return FakeResponse(200)

    monkeypatch.setattr(
        sync_preflight.urllib.request,
        "urlopen",
        fake_urlopen
    )

    import openai
    mock_openai = MagicMock()
    monkeypatch.setattr(openai, "OpenAI", lambda **kw: mock_openai)

    sync_preflight.run_preflight_checks(
        protocol="wifi",
        device="dummy",
        model="dummy-model",
    )

    # Verify that we sent exactly 2 requests (one POST, one DELETE)
    assert len(requests_sent) == 2
    
    # 1. Verify the POST request
    post_req = requests_sent[0]
    assert post_req.method == "POST"
    assert post_req.full_url == "http://10.0.0.1:8000/ingest/runs"
    import json
    post_payload = json.loads(post_req.data.decode("utf-8"))
    test_run_id = post_payload["run_id"]
    assert test_run_id.startswith("f000")

    # 2. Verify the DELETE request targets the exact test_run_id posted
    delete_req = requests_sent[1]
    assert delete_req.method == "DELETE"
    assert delete_req.full_url == f"http://10.0.0.1:8000/ingest/runs/{test_run_id}"



def test_run_preflight_checks_dashboard_post_fail(isolated_home, monkeypatch):
    _write_env(isolated_home)
    _stub_ssh_ok(monkeypatch)
    _stub_healthz_ok(monkeypatch)

    class FakeResponse:
        def __init__(self, status):
            self.status = status
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr(
        sync_preflight.urllib.request,
        "urlopen",
        lambda *args, **kw: FakeResponse(500)
    )

    with pytest.raises(SystemExit) as exc:
        sync_preflight.run_preflight_checks(
            protocol="wifi",
            device="dummy",
        )
    assert exc.value.code == 2


def test_run_preflight_checks_llm_fail(isolated_home, monkeypatch):
    _write_env(isolated_home)
    _stub_ssh_ok(monkeypatch)
    _stub_healthz_ok(monkeypatch)

    class FakeResponse:
        def __init__(self, status):
            self.status = status
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr(
        sync_preflight.urllib.request,
        "urlopen",
        lambda *args, **kw: FakeResponse(200)
    )

    import openai
    mock_client = MagicMock()
    mock_client.chat.completions.create.side_effect = Exception("LLM connection refused")
    monkeypatch.setattr(openai, "OpenAI", lambda **kw: mock_client)

    with pytest.raises(SystemExit) as exc:
        sync_preflight.run_preflight_checks(
            protocol="wifi",
            device="dummy",
        )
    assert exc.value.code == 2


def test_run_preflight_checks_bt_ports_fail(isolated_home, monkeypatch):
    _write_env(isolated_home)
    _stub_ssh_ok(monkeypatch)
    _stub_healthz_ok(monkeypatch)

    class FakeResponse:
        def __init__(self, status):
            self.status = status
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr(
        sync_preflight.urllib.request,
        "urlopen",
        lambda *args, **kw: FakeResponse(200)
    )

    import openai
    mock_openai = MagicMock()
    monkeypatch.setattr(openai, "OpenAI", lambda **kw: mock_openai)
    monkeypatch.setattr(sync_preflight.os.path, "exists", lambda path: False)

    with pytest.raises(SystemExit) as exc:
        sync_preflight.run_preflight_checks(
            protocol="bt",
            device="dummy",
            host_port="/dev/ttyUSB1",
            target_port="/dev/ttyUSB2",
        )
    assert exc.value.code == 2


def test_run_preflight_checks_fiveg_sdr_fail(isolated_home, monkeypatch):
    _write_env(isolated_home)
    _stub_ssh_ok(monkeypatch)
    _stub_healthz_ok(monkeypatch)

    class FakeResponse:
        def __init__(self, status):
            self.status = status
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr(
        sync_preflight.urllib.request,
        "urlopen",
        lambda *args, **kw: FakeResponse(200)
    )

    import openai
    mock_openai = MagicMock()
    monkeypatch.setattr(openai, "OpenAI", lambda **kw: mock_openai)
    monkeypatch.setattr(sync_preflight.shutil, "which", lambda cmd: "/usr/local/bin/uhd_find_devices")
    
    def fake_run(cmd, *args, **kwargs):
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="No devices found", stderr="")
    monkeypatch.setattr(sync_preflight.subprocess, "run", fake_run)

    with pytest.raises(SystemExit) as exc:
        sync_preflight.run_preflight_checks(
            protocol="fiveg",
            device="dummy",
        )
    assert exc.value.code == 2


def test_run_preflight_checks_fiveg_adb_fail(isolated_home, monkeypatch):
    _write_env(isolated_home)
    _stub_ssh_ok(monkeypatch)
    _stub_healthz_ok(monkeypatch)

    class FakeResponse:
        def __init__(self, status):
            self.status = status
        def __enter__(self):
            return self
        def __exit__(self, *args):
            pass

    monkeypatch.setattr(
        sync_preflight.urllib.request,
        "urlopen",
        lambda *args, **kw: FakeResponse(200)
    )

    import openai
    mock_openai = MagicMock()
    monkeypatch.setattr(openai, "OpenAI", lambda **kw: mock_openai)
    monkeypatch.setattr(sync_preflight.shutil, "which", lambda cmd: "/usr/local/bin/uhd_find_devices")
    monkeypatch.setattr(sync_preflight.os.path, "exists", lambda path: True)

    def fake_run(cmd, *args, **kwargs):
        if "uhd_find_devices" in cmd[0]:
            return subprocess.CompletedProcess(cmd, returncode=0, stdout="-- UHD Device 0", stderr="")
        elif "adb" in cmd[0]:
            return subprocess.CompletedProcess(cmd, returncode=1, stdout="offline", stderr="error: device offline")
        return subprocess.CompletedProcess(cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(sync_preflight.subprocess, "run", fake_run)

    with pytest.raises(SystemExit) as exc:
        sync_preflight.run_preflight_checks(
            protocol="fiveg",
            device="dummy",
            adb_serial="12345"
        )
    assert exc.value.code == 2

