"""Tests for crash_tools: analyze_crash_log, compare_crashes, read_device_log."""

import json
import os
import tempfile
import shutil
from unittest.mock import MagicMock

import pytest


@pytest.fixture
def tmp_log_dir():
    tmpdir = tempfile.mkdtemp()
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def crash_tools():
    """Build crash tools with a mocked td_utils."""
    td_utils = MagicMock()
    td_utils.monitor_log = "monitor.1.txt"
    td_utils.crash_id_field = "sModemReason"
    from tools.crash_tools import get_crash_tools

    tools = get_crash_tools(td_utils)
    return tools, td_utils


class TestAnalyzeCrashLog:
    def test_missing_monitor_log(self, crash_tools, tmp_log_dir):
        tools, _ = crash_tools
        _, handler = tools["analyze_crash_log"]
        result = json.loads(handler({"log_folder": tmp_log_dir}))
        assert "error" in result
        assert "not found" in result["error"]

    def test_parses_crash_ids(self, crash_tools, tmp_log_dir):
        tools, td_utils = crash_tools
        _, handler = tools["analyze_crash_log"]

        # Write a monitor log with sModemReason
        monitor_path = os.path.join(tmp_log_dir, "monitor.1.txt")
        with open(monitor_path, "w") as f:
            f.write("some preamble\nsModemReason=FATAL_CRASH_001\nsome aftermath\n")

        td_utils.crash_ids_from_trace_log.return_value = [
            ("FATAL_CRASH_001", "2026-01-01T00:00:00"),
        ]

        result = json.loads(handler({"log_folder": tmp_log_dir}))
        assert result["crash_count"] == 1
        assert result["crash_ids"][0]["crash_id"] == "FATAL_CRASH_001"
        assert "sModemReason" in result["crash_context"]

    def test_no_smodemreason_empty_context(self, crash_tools, tmp_log_dir):
        tools, td_utils = crash_tools
        _, handler = tools["analyze_crash_log"]

        monitor_path = os.path.join(tmp_log_dir, "monitor.1.txt")
        with open(monitor_path, "w") as f:
            f.write("no crash markers here\njust normal log lines\n")

        td_utils.crash_ids_from_trace_log.return_value = []

        result = json.loads(handler({"log_folder": tmp_log_dir}))
        assert result["crash_count"] == 0
        assert result["crash_ids"] == []
        assert result["crash_context"] == ""

    def test_multiple_crash_ids(self, crash_tools, tmp_log_dir):
        tools, td_utils = crash_tools
        _, handler = tools["analyze_crash_log"]

        monitor_path = os.path.join(tmp_log_dir, "monitor.1.txt")
        with open(monitor_path, "w") as f:
            f.write("sModemReason=CRASH_A\nsModemReason=CRASH_B\n")

        td_utils.crash_ids_from_trace_log.return_value = [
            ("CRASH_A", "t1"),
            ("CRASH_B", "t2"),
        ]

        result = json.loads(handler({"log_folder": tmp_log_dir}))
        assert result["crash_count"] == 2

    def test_exception_returns_error(self, crash_tools, tmp_log_dir):
        tools, td_utils = crash_tools
        _, handler = tools["analyze_crash_log"]

        monitor_path = os.path.join(tmp_log_dir, "monitor.1.txt")
        with open(monitor_path, "w") as f:
            f.write("data")

        td_utils.crash_ids_from_trace_log.side_effect = RuntimeError("parse failed")

        result = json.loads(handler({"log_folder": tmp_log_dir}))
        assert "error" in result
        assert "parse failed" in result["error"]

    def test_relative_path_resolved(self, crash_tools, tmp_log_dir):
        tools, td_utils = crash_tools
        _, handler = tools["analyze_crash_log"]

        # Use a relative path — handler should resolve it
        result = json.loads(handler({"log_folder": "nonexistent_relative_dir"}))
        assert "error" in result
        assert "not found" in result["error"]

    def test_crash_context_truncated_to_1000(self, crash_tools, tmp_log_dir):
        tools, td_utils = crash_tools
        _, handler = tools["analyze_crash_log"]

        monitor_path = os.path.join(tmp_log_dir, "monitor.1.txt")
        # Write a very long log with sModemReason in the middle
        with open(monitor_path, "w") as f:
            f.write("A" * 500 + "sModemReason=CRASH" + "B" * 2000)

        td_utils.crash_ids_from_trace_log.return_value = [("CRASH", "t1")]

        result = json.loads(handler({"log_folder": tmp_log_dir}))
        assert len(result["crash_context"]) <= 1000


class TestCompareCrashes:
    def test_same_crash_ids(self, crash_tools):
        tools, _ = crash_tools
        _, handler = tools["compare_crashes"]
        result = json.loads(
            handler({"crash_id_1": "CRASH_001", "crash_id_2": "CRASH_001"})
        )
        assert result["same_root_cause"] is True

    def test_different_crash_ids(self, crash_tools):
        tools, _ = crash_tools
        _, handler = tools["compare_crashes"]
        result = json.loads(
            handler({"crash_id_1": "CRASH_001", "crash_id_2": "CRASH_002"})
        )
        assert result["same_root_cause"] is False

    def test_whitespace_stripped(self, crash_tools):
        tools, _ = crash_tools
        _, handler = tools["compare_crashes"]
        result = json.loads(
            handler({"crash_id_1": "  CRASH_001  ", "crash_id_2": "CRASH_001"})
        )
        assert result["same_root_cause"] is True

    def test_returns_both_ids(self, crash_tools):
        tools, _ = crash_tools
        _, handler = tools["compare_crashes"]
        result = json.loads(handler({"crash_id_1": "A", "crash_id_2": "B"}))
        assert result["crash_id_1"] == "A"
        assert result["crash_id_2"] == "B"


class TestReadDeviceLog:
    def test_file_not_found(self, crash_tools):
        tools, _ = crash_tools
        _, handler = tools["read_device_log"]
        result = handler({"log_path": "/nonexistent/path/log.txt"})
        assert "not found" in result.lower()

    def test_reads_log_file(self, crash_tools, tmp_log_dir):
        tools, _ = crash_tools
        _, handler = tools["read_device_log"]

        log_path = os.path.join(tmp_log_dir, "test.log")
        with open(log_path, "w") as f:
            for i in range(10):
                f.write(f"line {i}\n")

        result = json.loads(handler({"log_path": log_path}))
        assert result["total_lines"] == 10
        assert result["lines_returned"] == 10
        assert result["offset"] == 0
        assert "line 0" in result["content"]
        assert "line 9" in result["content"]

    def test_offset_and_limit(self, crash_tools, tmp_log_dir):
        tools, _ = crash_tools
        _, handler = tools["read_device_log"]

        log_path = os.path.join(tmp_log_dir, "test.log")
        with open(log_path, "w") as f:
            for i in range(20):
                f.write(f"line {i}\n")

        result = json.loads(
            handler({"log_path": log_path, "offset": 5, "max_lines": 3})
        )
        assert result["total_lines"] == 20
        assert result["offset"] == 5
        assert result["lines_returned"] == 3
        assert "line 5" in result["content"]
        assert "line 7" in result["content"]
        assert "line 8" not in result["content"]

    def test_max_lines_capped_at_200(self, crash_tools, tmp_log_dir):
        tools, _ = crash_tools
        _, handler = tools["read_device_log"]

        log_path = os.path.join(tmp_log_dir, "big.log")
        with open(log_path, "w") as f:
            for i in range(500):
                f.write(f"line {i}\n")

        result = json.loads(handler({"log_path": log_path, "max_lines": 999}))
        assert result["lines_returned"] == 200

    def test_default_offset_zero(self, crash_tools, tmp_log_dir):
        tools, _ = crash_tools
        _, handler = tools["read_device_log"]

        log_path = os.path.join(tmp_log_dir, "small.log")
        with open(log_path, "w") as f:
            f.write("only line\n")

        result = json.loads(handler({"log_path": log_path}))
        assert result["offset"] == 0
        assert result["lines_returned"] == 1

    def test_relative_path_resolved(self, crash_tools):
        tools, _ = crash_tools
        _, handler = tools["read_device_log"]
        result = handler({"log_path": "relative/path.log"})
        assert "not found" in result.lower()
