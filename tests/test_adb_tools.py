"""Tests for ADB tools — mocked subprocess, no real device needed."""

import json
import subprocess
from unittest.mock import patch, MagicMock


from tools.adb_tools import get_adb_tools, _run_adb, _filter_lines


# ---- Schema / registration tests ----


def test_get_adb_tools_returns_five_tools():
    tools = get_adb_tools()
    assert len(tools) == 5
    expected = {
        "adb_logcat",
        "adb_device_state",
        "adb_dmesg",
        "adb_dumpsys",
        "adb_modem_health",
    }
    assert set(tools.keys()) == expected


def test_tool_schema_structure():
    tools = get_adb_tools()
    for name, (schema, handler) in tools.items():
        assert schema["name"] == name
        assert "description" in schema
        assert "input_schema" in schema
        assert schema["input_schema"]["type"] == "object"
        assert callable(handler)


# ---- _run_adb tests ----


@patch("tools.adb_tools.subprocess.run")
def test_run_adb_success(mock_run):
    mock_run.return_value = MagicMock(returncode=0, stdout="ok\n", stderr="")
    rc, out, err = _run_adb("shell", "getprop", "foo")
    assert rc == 0
    assert out == "ok\n"
    assert err == ""


@patch(
    "tools.adb_tools.subprocess.run",
    side_effect=subprocess.TimeoutExpired(cmd="adb", timeout=10),
)
def test_run_adb_timeout(mock_run):
    rc, out, err = _run_adb("shell", "getprop", "foo")
    assert rc == -1
    assert "timed out" in err


@patch("tools.adb_tools.subprocess.run", side_effect=FileNotFoundError)
def test_run_adb_missing_binary(mock_run):
    rc, out, err = _run_adb("shell", "getprop", "foo")
    assert rc == -1
    assert "not found" in err


# ---- _filter_lines tests ----


def test_filter_lines_no_pattern():
    lines, truncated = _filter_lines("a\nb\nc", max_lines=10)
    assert lines == ["a", "b", "c"]
    assert not truncated


def test_filter_lines_with_pattern():
    lines, truncated = _filter_lines(
        "error: bad\ninfo: ok\nerror: worse", grep_pattern="error"
    )
    assert len(lines) == 2
    assert all("error" in l for l in lines)


def test_filter_lines_truncation():
    text = "\n".join(f"line{i}" for i in range(100))
    lines, truncated = _filter_lines(text, max_lines=10)
    assert len(lines) == 10
    assert truncated


def test_filter_lines_bad_regex():
    lines, truncated = _filter_lines("hello", grep_pattern="[invalid")
    assert "invalid grep_pattern" in lines[0]


# ---- adb_logcat handler tests ----


@patch("tools.adb_tools._run_adb")
def test_adb_logcat_success(mock_adb):
    mock_adb.return_value = (0, "line1\nline2\nmodem error\n", "")
    tools = get_adb_tools()
    _, handler = tools["adb_logcat"]
    result = json.loads(handler({"minutes": 3, "grep_pattern": "modem"}))
    assert result["line_count"] == 1
    assert "modem" in result["content"]


@patch("tools.adb_tools._run_adb")
def test_adb_logcat_error(mock_adb):
    mock_adb.return_value = (1, "", "device not found")
    tools = get_adb_tools()
    _, handler = tools["adb_logcat"]
    result = json.loads(handler({}))
    assert "error" in result


# ---- adb_device_state handler tests ----


@patch("tools.adb_tools._run_adb")
def test_adb_device_state(mock_adb):
    def side_effect(*args, **kwargs):
        cmd = args[0] if args else ""
        if "getprop" in args:
            prop = args[-1]
            values = {
                "gsm.version.baseband": "MOLY.NR15.R3",
                "gsm.sim.state": "READY",
            }
            return (0, values.get(prop, ""), "")
        if "cat" in args:
            return (0, "12345.67 8901.23", "")
        if "dumpsys" in args:
            return (0, "mServiceState=IN_SERVICE\nmSignalStrength=-85", "")
        return (0, "", "")

    mock_adb.side_effect = side_effect
    tools = get_adb_tools()
    _, handler = tools["adb_device_state"]
    result = json.loads(handler({}))
    assert result["baseband_version"] == "MOLY.NR15.R3"
    assert result["sim_state"] == "READY"
    assert result["uptime_seconds"] == 12345.67


# ---- adb_dmesg handler tests ----


@patch("tools.adb_tools._run_adb")
def test_adb_dmesg_success(mock_adb):
    mock_adb.return_value = (0, "[1.234] modem crash\n[1.235] normal msg\n", "")
    tools = get_adb_tools()
    _, handler = tools["adb_dmesg"]
    result = json.loads(handler({"grep_pattern": "modem"}))
    assert result["line_count"] == 1


# ---- adb_dumpsys handler tests ----


@patch("tools.adb_tools._run_adb")
def test_adb_dumpsys_success(mock_adb):
    mock_adb.return_value = (0, "registry data\nmore data", "")
    tools = get_adb_tools()
    _, handler = tools["adb_dumpsys"]
    result = json.loads(handler({"service": "telephony.registry"}))
    assert result["service"] == "telephony.registry"
    assert result["line_count"] == 2


def test_adb_dumpsys_invalid_service():
    tools = get_adb_tools()
    _, handler = tools["adb_dumpsys"]
    result = json.loads(handler({"service": "evil_service"}))
    assert "error" in result
    assert "not allowed" in result["error"]


# ---- adb_modem_health handler tests ----


@patch("tools.adb_tools._run_adb")
def test_adb_modem_health_alive(mock_adb):
    mock_adb.side_effect = [
        (0, "MOLY.NR15.R3\n", ""),  # baseband
        (0, "READY\n", ""),  # sim
    ]
    tools = get_adb_tools()
    _, handler = tools["adb_modem_health"]
    result = json.loads(handler({}))
    assert result["modem_alive"] is True
    assert result["baseband_version"] == "MOLY.NR15.R3"


@patch("tools.adb_tools._run_adb")
def test_adb_modem_health_dead_no_wait(mock_adb):
    mock_adb.side_effect = [
        (0, "\n", ""),  # empty baseband = dead
        (0, "ABSENT\n", ""),
    ]
    tools = get_adb_tools()
    _, handler = tools["adb_modem_health"]
    result = json.loads(handler({}))
    assert result["modem_alive"] is False


@patch("tools.adb_tools.time.sleep")
@patch("tools.adb_tools._run_adb")
def test_adb_modem_health_wait_recovery(mock_adb, mock_sleep):
    # First check: dead. Second check (after poll): alive.
    mock_adb.side_effect = [
        (0, "\n", ""),  # first check baseband - dead
        (0, "ABSENT\n", ""),  # first check sim
        (0, "MOLY.NR15.R3\n", ""),  # second check baseband - alive
        (0, "READY\n", ""),  # second check sim
    ]
    tools = get_adb_tools()
    _, handler = tools["adb_modem_health"]
    result = json.loads(handler({"wait_for_recovery": True, "poll_timeout": 10}))
    assert result["modem_alive"] is True
    assert "recovery_time_seconds" in result
