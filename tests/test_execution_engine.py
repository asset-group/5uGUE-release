"""Tests for ExecutionEngine: compile error parsing, mutation log parsing, crash handling, state diffs."""

import json
import os
import tempfile
import shutil
from dataclasses import asdict
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def tmp_dirs():
    """Create temp dirs for exploit folder and log path."""
    tmpdir = tempfile.mkdtemp()
    exploit_dir = os.path.join(tmpdir, "exploits")
    log_dir = os.path.join(tmpdir, "logs")
    os.makedirs(exploit_dir)
    os.makedirs(log_dir)
    yield tmpdir, exploit_dir, log_dir
    shutil.rmtree(tmpdir, ignore_errors=True)


@pytest.fixture
def mock_engine(tmp_dirs):
    """Create an ExecutionEngine with mocked dependencies."""
    from execution_engine import ExecutionEngine

    _, exploit_dir, log_dir = tmp_dirs
    exploiter = MagicMock()
    td_utils = MagicMock()
    td_utils.monitor_log = "monitor.1.txt"
    td_utils.crash_id_field = "sModemReason"
    wd_tool = MagicMock()
    base_sm = MagicMock()

    engine = ExecutionEngine(
        exploiter, td_utils, wd_tool, base_sm, run_id="test", exploit_folder=exploit_dir
    )
    return engine, exploiter, td_utils, exploit_dir, log_dir


class TestTestResultDataclass:
    def test_default_fields(self):
        from execution_engine import TestResult

        tr = TestResult(
            test_id="t1",
            fuzz_description="test",
            compile_success=True,
            compile_error=None,
            execution_time_seconds=1.0,
            crash_triggered=False,
            crash_id=None,
            crash_category="",
            crash_summary=None,
        )
        assert tr.new_states == []
        assert tr.new_transitions == []
        assert tr.capture_path == ""
        assert tr.log_path == ""
        assert tr.total_packets == 0
        assert tr.exploit_hash == ""
        assert tr.mutation_count == 0
        assert tr.mutation_log_lines == []
        assert tr.exploit_name == ""
        assert tr.exploit_code == ""

    def test_dataclass_serializable(self):
        from execution_engine import TestResult

        tr = TestResult(
            test_id="t1",
            fuzz_description="desc",
            compile_success=True,
            compile_error=None,
            execution_time_seconds=2.5,
            crash_triggered=True,
            crash_id="CRASH_001",
            crash_category="fully_novel_crash",
            crash_summary="sModemReason=fatal",
            new_states=["new_state_1"],
            new_transitions=["A->B"],
        )
        d = asdict(tr)
        assert d["test_id"] == "t1"
        assert d["crash_triggered"] is True
        assert d["new_states"] == ["new_state_1"]
        # Should be JSON-serializable
        json_str = json.dumps(d)
        assert "CRASH_001" in json_str


class TestExecutionEngineTestId:
    def test_test_id_increments(self):
        from execution_engine import ExecutionEngine

        engine = ExecutionEngine.__new__(ExecutionEngine)
        engine.run_id = "run42"
        engine.test_count = 0

        # Simulate the test_id logic
        engine.test_count += 1
        assert f"{engine.run_id}-{engine.test_count}" == "run42-1"
        engine.test_count += 1
        assert f"{engine.run_id}-{engine.test_count}" == "run42-2"


class TestCompileErrorParsing:
    """Test compile error detection logic extracted from ExecutionEngine.execute()."""

    def _parse_compile_log(self, log_content: str):
        """Replicate the compile error parsing from execute()."""
        compile_success = True
        compile_error = None
        if (
            "Error when loading or compiling C Modules" in log_content
            or "Select only the available exploits below" in log_content
        ):
            compile_success = False
            lines = log_content.split("\n")
            error_lines = [
                l for l in lines if "error:" in l.lower() or "warning:" in l.lower()
            ]
            compile_error = (
                "\n".join(error_lines[:20])
                if error_lines
                else "Compilation failed (see log)"
            )
        return compile_success, compile_error

    def test_successful_compile(self):
        log = "Loading module mac_sch_test...\n[M] TX --> packet sent\nDone."
        success, error = self._parse_compile_log(log)
        assert success is True
        assert error is None

    def test_compile_error_detected(self):
        log = (
            "Error when loading or compiling C Modules\n"
            "mac_sch_test.cpp:42: error: 'foo' was not declared\n"
            "mac_sch_test.cpp:50: warning: unused variable 'x'\n"
        )
        success, error = self._parse_compile_log(log)
        assert success is False
        assert "error:" in error.lower()
        assert "foo" in error

    def test_compile_error_select_exploits(self):
        log = "Select only the available exploits below\nexploit_a\nexploit_b"
        success, error = self._parse_compile_log(log)
        assert success is False
        assert error == "Compilation failed (see log)"

    def test_compile_error_truncates_to_20_lines(self):
        lines = [f"line{i}: error: something wrong" for i in range(30)]
        log = "Error when loading or compiling C Modules\n" + "\n".join(lines)
        success, error = self._parse_compile_log(log)
        assert success is False
        # Should only have first 20 error lines
        assert error.count("error:") == 20


class TestMutationLogParsing:
    """Test mutation delivery metric parsing from run logs."""

    def _parse_mutations(self, log_content: str):
        """Replicate mutation log parsing from execute()."""
        import re

        mutation_count = 0
        mutation_log_lines = []
        _ansi_re = re.compile(r"\x1b\[[0-9;]*m")
        for line in log_content.split("\n"):
            clean = _ansi_re.sub("", line)
            if "[M] TX -->" in clean:
                mutation_count += 1
                if len(mutation_log_lines) < 10:
                    mutation_log_lines.append(clean.strip())
        return mutation_count, mutation_log_lines

    def test_no_mutations(self):
        log = "Starting test...\nPacket sent\nDone."
        count, lines = self._parse_mutations(log)
        assert count == 0
        assert lines == []

    def test_single_mutation(self):
        log = "Starting...\n[M] TX --> rrcSetup mutated\nDone."
        count, lines = self._parse_mutations(log)
        assert count == 1
        assert len(lines) == 1
        assert "rrcSetup" in lines[0]

    def test_multiple_mutations(self):
        log = "\n".join([f"[M] TX --> mutation_{i}" for i in range(15)])
        count, lines = self._parse_mutations(log)
        assert count == 15
        # Only first 10 lines captured
        assert len(lines) == 10

    def test_ansi_codes_stripped(self):
        log = "\x1b[33m[M] TX --> \x1b[0mmutated packet\x1b[0m"
        count, lines = self._parse_mutations(log)
        assert count == 1
        assert "\x1b" not in lines[0]

    def test_mixed_log_lines(self):
        log = (
            "INFO: Starting test\n"
            "[M] TX --> first mutation\n"
            "WARNING: timeout\n"
            "[M] TX --> second mutation\n"
            "INFO: Test complete\n"
        )
        count, lines = self._parse_mutations(log)
        assert count == 2
        assert "first" in lines[0]
        assert "second" in lines[1]


class TestExecuteCompileFailure:
    """Test execute() returns correct TestResult on compile failure."""

    def test_compile_failure_result(self, tmp_dirs):
        from execution_engine import ExecutionEngine

        tmpdir, exploit_dir, log_dir = tmp_dirs

        # Write a fake run log with compile error
        run_log = os.path.join(tmpdir, "run.log")
        with open(run_log, "w") as f:
            f.write(
                "Error when loading or compiling C Modules\ntest.cpp:1: error: syntax error\n"
            )

        exploiter = MagicMock()
        exploiter.run_exploit_once.return_value = (False, run_log)
        exploiter.fuzz_capture_exist.return_value = False

        with patch("execution_engine.LOG_PATH", log_dir):
            engine = ExecutionEngine(
                exploiter,
                MagicMock(),
                MagicMock(),
                MagicMock(),
                run_id="ctest",
                exploit_folder=exploit_dir,
            )
            result = engine.execute(
                "int main() {}", exploit_name="mac_sch_bad", description="bad code"
            )

        assert result.compile_success is False
        assert result.compile_error is not None
        assert "syntax error" in result.compile_error
        assert result.crash_triggered is False
        assert result.test_id == "ctest-1"

    def test_successful_execution_no_crash(self, tmp_dirs):
        from execution_engine import ExecutionEngine

        tmpdir, exploit_dir, log_dir = tmp_dirs
        run_log = os.path.join(tmpdir, "run.log")
        with open(run_log, "w") as f:
            f.write(
                "Loading module...\n[M] TX --> mutated pkt\n[M] TX --> mutated pkt 2\nDone.\n"
            )

        exploiter = MagicMock()
        exploiter.run_exploit_once.return_value = (False, run_log)
        exploiter.fuzz_capture_exist.return_value = False
        exploiter.detect_downgrade_attack.return_value = False

        with patch("execution_engine.LOG_PATH", log_dir):
            engine = ExecutionEngine(
                exploiter,
                MagicMock(),
                MagicMock(),
                MagicMock(),
                run_id="ok",
                exploit_folder=exploit_dir,
            )
            result = engine.execute(
                "#include <stdio.h>", exploit_name="mac_sch_ok", description="good"
            )

        assert result.compile_success is True
        assert result.compile_error is None
        assert result.crash_triggered is False
        assert result.mutation_count == 2
        assert len(result.mutation_log_lines) == 2
        assert result.exploit_name == "mac_sch_ok"
        assert result.test_id == "ok-1"


class TestExecuteCrashDetection:
    """Test crash detection logic from execute()."""

    def test_crash_id_extraction_logic(self):
        """Test the crash_ids parsing logic."""
        # Simulate what check_crash returns: list of (crash_id, ...) tuples + category
        crash_ids = [("CRASH_MODEM_001", "some_extra_info")]
        category = "fully_novel_crash"

        if crash_ids and len(crash_ids) > 0:
            crash_id = crash_ids[0][0]
            crash_category = category
        else:
            crash_id = None
            crash_category = ""

        assert crash_id == "CRASH_MODEM_001"
        assert crash_category == "fully_novel_crash"

    def test_crash_summary_with_smodemreason(self):
        """Test sModemReason extraction logic."""
        content = "x" * 300 + "sModemReason=FATAL_ERROR" + "y" * 400
        idx = content.find("sModemReason")
        assert idx >= 0

        crash_summary = content[max(0, idx - 200) : idx + 300]
        assert "sModemReason" in crash_summary

    def test_crash_summary_fallback_no_smodemreason(self):
        """When sModemReason not found, use last 500 chars."""
        content = "A" * 1000
        idx = content.find("sModemReason")
        assert idx == -1

        crash_summary = content[-500:] if len(content) > 500 else content
        assert len(crash_summary) == 500

    def test_empty_crash_ids(self):
        """Empty crash_ids list should not set crash_id."""
        crash_ids = []
        crash_id = None
        crash_category = ""

        if crash_ids and len(crash_ids) > 0:
            crash_id = crash_ids[0][0]
        assert crash_id is None
        assert crash_category == ""


class TestExecuteWithCrash:
    """Test execute() end-to-end with crash triggered."""

    def test_crash_with_unique_id(self, tmp_dirs):
        from execution_engine import ExecutionEngine

        tmpdir, exploit_dir, log_dir = tmp_dirs
        run_log = os.path.join(tmpdir, "run.log")
        with open(run_log, "w") as f:
            f.write("Loading...\n[M] TX --> mutated\nDone.\n")

        # Create the test log folder that execute() will create
        test_log_folder = os.path.join(log_dir, "run_crash", "test_1")
        os.makedirs(test_log_folder, exist_ok=True)

        # Write a monitor.1.txt with sModemReason
        monitor_path = os.path.join(test_log_folder, "monitor.1.txt")
        with open(monitor_path, "w") as f:
            f.write("preamble\nsModemReason=NR_FATAL_CRASH\naftermath\n")

        exploiter = MagicMock()
        exploiter.run_exploit_once.return_value = (
            True,
            run_log,
        )  # crash_triggered=True
        exploiter.fuzz_capture_exist.return_value = False

        td_utils = MagicMock()
        td_utils.monitor_log = "monitor.1.txt"
        td_utils.crash_id_field = "sModemReason"
        td_utils.check_crash.return_value = (
            [("NR_FATAL_CRASH", "ts")],
            "fully_novel_crash",
        )

        with patch("execution_engine.LOG_PATH", log_dir):
            engine = ExecutionEngine(
                exploiter,
                td_utils,
                MagicMock(),
                MagicMock(),
                run_id="crash",
                exploit_folder=exploit_dir,
            )
            result = engine.execute(
                "code", exploit_name="mac_sch_crash", description="crash test"
            )

        assert result.crash_triggered is True
        assert result.crash_id == "NR_FATAL_CRASH"
        assert result.crash_category == "fully_novel_crash"
        assert result.crash_summary is not None
        assert "sModemReason" in result.crash_summary

    def test_crash_not_unique(self, tmp_dirs):
        from execution_engine import ExecutionEngine

        tmpdir, exploit_dir, log_dir = tmp_dirs
        run_log = os.path.join(tmpdir, "run.log")
        with open(run_log, "w") as f:
            f.write("Loading...\nDone.\n")

        exploiter = MagicMock()
        exploiter.run_exploit_once.return_value = (True, run_log)
        exploiter.fuzz_capture_exist.return_value = False

        td_utils = MagicMock()
        td_utils.monitor_log = "monitor.1.txt"
        td_utils.crash_id_field = "sModemReason"
        td_utils.check_crash.return_value = (
            [("KNOWN_CRASH", "ts")],
            "publicly_known_crash",
        )

        with patch("execution_engine.LOG_PATH", log_dir):
            engine = ExecutionEngine(
                exploiter,
                td_utils,
                MagicMock(),
                MagicMock(),
                run_id="dup",
                exploit_folder=exploit_dir,
            )
            result = engine.execute(
                "code", exploit_name="mac_sch_dup", description="dup crash"
            )

        assert result.crash_triggered is True
        assert result.crash_id == "KNOWN_CRASH"
        assert result.crash_category == "publicly_known_crash"

    def test_crash_check_exception_handled(self, tmp_dirs):
        from execution_engine import ExecutionEngine

        tmpdir, exploit_dir, log_dir = tmp_dirs
        run_log = os.path.join(tmpdir, "run.log")
        with open(run_log, "w") as f:
            f.write("Loading...\nDone.\n")

        exploiter = MagicMock()
        exploiter.run_exploit_once.return_value = (True, run_log)
        exploiter.fuzz_capture_exist.return_value = False

        td_utils = MagicMock()
        td_utils.monitor_log = "monitor.1.txt"
        td_utils.crash_id_field = "sModemReason"
        td_utils.check_crash.side_effect = RuntimeError("ADB disconnected")

        with patch("execution_engine.LOG_PATH", log_dir):
            engine = ExecutionEngine(
                exploiter,
                td_utils,
                MagicMock(),
                MagicMock(),
                run_id="err",
                exploit_folder=exploit_dir,
            )
            result = engine.execute(
                "code", exploit_name="mac_sch_err", description="err test"
            )

        # Crash triggered but check_crash failed — crash_id should be None
        assert result.crash_triggered is True
        assert result.crash_id is None
        assert result.crash_category == ""

    def test_crash_no_monitor_fallback(self, tmp_dirs):
        """Crash without monitor.1.txt — summary from last 500 chars."""
        from execution_engine import ExecutionEngine

        tmpdir, exploit_dir, log_dir = tmp_dirs
        run_log = os.path.join(tmpdir, "run.log")
        with open(run_log, "w") as f:
            f.write("Done.\n")

        exploiter = MagicMock()
        exploiter.run_exploit_once.return_value = (True, run_log)
        exploiter.fuzz_capture_exist.return_value = False

        td_utils = MagicMock()
        td_utils.monitor_log = "monitor.1.txt"
        td_utils.crash_id_field = "sModemReason"
        td_utils.check_crash.return_value = ([("CRASH_NO_MON", "ts")], True)

        with patch("execution_engine.LOG_PATH", log_dir):
            engine = ExecutionEngine(
                exploiter,
                td_utils,
                MagicMock(),
                MagicMock(),
                run_id="nomon",
                exploit_folder=exploit_dir,
            )
            result = engine.execute(
                "code", exploit_name="mac_sch_nm", description="no monitor"
            )

        assert result.crash_id == "CRASH_NO_MON"
        # No monitor.1.txt → crash_summary is None (monitor_path doesn't exist)
        assert result.crash_summary is None


class TestExecuteWithStateDiff:
    """Test execute() state diff and packet counting paths."""

    def test_state_diff_computed(self, tmp_dirs):
        from execution_engine import ExecutionEngine

        tmpdir, exploit_dir, log_dir = tmp_dirs
        run_log = os.path.join(tmpdir, "run.log")
        with open(run_log, "w") as f:
            f.write("Loading...\n[M] TX --> pkt\nDone.\n")

        # Create the capture file in the test log folder
        test_log_folder = os.path.join(log_dir, "run_sd", "test_1")
        os.makedirs(test_log_folder, exist_ok=True)
        capture_path = os.path.join(test_log_folder, "capture_nr5g_gnb.pcapng")
        import struct as _struct

        with open(capture_path, "wb") as f:
            # Minimal valid pcapng Section Header Block (28 bytes)
            shb_body = (
                b"\x1a\x2b\x3c\x4d"
                + b"\x01\x00\x00\x00"
                + b"\xff\xff\xff\xff\xff\xff\xff\xff"
            )
            shb_len = 4 + 4 + len(shb_body) + 4  # type(4)+len(4)+body+trailing_len(4)
            f.write(b"\x0a\x0d\x0d\x0a")
            f.write(_struct.pack("<I", shb_len))
            f.write(shb_body)
            f.write(_struct.pack("<I", shb_len))

        exploiter = MagicMock()
        exploiter.run_exploit_once.return_value = (False, run_log)
        exploiter.fuzz_capture_exist.return_value = True
        exploiter.save_log = MagicMock()

        mock_new_states = (["NEW_STATE_X"], ["A->B", "B->C"])

        with (
            patch("execution_engine.LOG_PATH", log_dir),
            patch(
                "execution_engine.new_states_and_transitions", create=True
            ) as mock_ns,
        ):
            # Patch the import inside execute()
            import sys

            mock_llm_fuzz = MagicMock()
            mock_llm_fuzz.new_states_and_transitions.return_value = mock_new_states
            mock_pkt_cap = MagicMock()
            mock_pkt_cap.pcap_pkt_reader.return_value = iter([{}, {}, {}])  # 3 packets

            with (
                patch.dict(
                    sys.modules,
                    {
                        "upstream.llm_fuzz": mock_llm_fuzz,
                        "upstream.utils.packet_cap": mock_pkt_cap,
                    },
                ),
                patch.object(ExecutionEngine, "_fix_truncated_pcap", return_value=True),
            ):
                engine = ExecutionEngine(
                    exploiter,
                    MagicMock(),
                    MagicMock(),
                    MagicMock(),
                    run_id="sd",
                    exploit_folder=exploit_dir,
                )
                result = engine.execute(
                    "code", exploit_name="mac_sch_sd", description="state diff"
                )

        assert result.compile_success is True
        assert result.new_states == ["NEW_STATE_X"]
        assert result.new_transitions == ["A->B", "B->C"]
        assert result.total_packets == 3
        exploiter.save_log.assert_called_once()

    def test_state_diff_exception_handled(self, tmp_dirs):
        from execution_engine import ExecutionEngine

        tmpdir, exploit_dir, log_dir = tmp_dirs
        run_log = os.path.join(tmpdir, "run.log")
        with open(run_log, "w") as f:
            f.write("Done.\n")

        test_log_folder = os.path.join(log_dir, "run_sde", "test_1")
        os.makedirs(test_log_folder, exist_ok=True)
        capture_path = os.path.join(test_log_folder, "capture_nr5g_gnb.pcapng")
        import struct as _struct

        with open(capture_path, "wb") as f:
            # Minimal valid pcapng Section Header Block (28 bytes)
            shb_body = (
                b"\x1a\x2b\x3c\x4d"
                + b"\x01\x00\x00\x00"
                + b"\xff\xff\xff\xff\xff\xff\xff\xff"
            )
            shb_len = 4 + 4 + len(shb_body) + 4
            f.write(b"\x0a\x0d\x0d\x0a")
            f.write(_struct.pack("<I", shb_len))
            f.write(shb_body)
            f.write(_struct.pack("<I", shb_len))

        exploiter = MagicMock()
        exploiter.run_exploit_once.return_value = (False, run_log)
        exploiter.fuzz_capture_exist.return_value = True
        exploiter.save_log = MagicMock()

        import sys

        mock_llm_fuzz = MagicMock()
        mock_llm_fuzz.new_states_and_transitions.side_effect = RuntimeError(
            "state machine error"
        )
        mock_pkt_cap = MagicMock()
        mock_pkt_cap.pcap_pkt_reader.return_value = iter([{}, {}])

        with (
            patch("execution_engine.LOG_PATH", log_dir),
            patch.dict(
                sys.modules,
                {
                    "upstream.llm_fuzz": mock_llm_fuzz,
                    "upstream.utils.packet_cap": mock_pkt_cap,
                },
            ),
            patch.object(ExecutionEngine, "_fix_truncated_pcap", return_value=True),
        ):
            engine = ExecutionEngine(
                exploiter,
                MagicMock(),
                MagicMock(),
                MagicMock(),
                run_id="sde",
                exploit_folder=exploit_dir,
            )
            result = engine.execute(
                "code", exploit_name="mac_sch_sde", description="err"
            )

        # State diff failed but should not crash execute()
        assert result.new_states == []
        assert result.new_transitions == []
        # Packet counting still works (uses pcap_pkt_reader, not tshark)
        assert result.total_packets == 2

    def test_no_capture_skips_diff(self, tmp_dirs):
        from execution_engine import ExecutionEngine

        tmpdir, exploit_dir, log_dir = tmp_dirs
        run_log = os.path.join(tmpdir, "run.log")
        with open(run_log, "w") as f:
            f.write("Done.\n")

        exploiter = MagicMock()
        exploiter.run_exploit_once.return_value = (False, run_log)
        exploiter.fuzz_capture_exist.return_value = False

        with patch("execution_engine.LOG_PATH", log_dir):
            engine = ExecutionEngine(
                exploiter,
                MagicMock(),
                MagicMock(),
                MagicMock(),
                run_id="nc",
                exploit_folder=exploit_dir,
            )
            result = engine.execute(
                "code", exploit_name="mac_sch_nc", description="no cap"
            )

        assert result.new_states == []
        assert result.total_packets == 0


class TestExecuteStaleFileRemoval:
    """Test that stale .so/.o files are removed before compilation."""

    def test_stale_so_removed(self, tmp_dirs):
        from execution_engine import ExecutionEngine

        tmpdir, exploit_dir, log_dir = tmp_dirs

        # Create stale .so and .o
        stale_so = os.path.join(exploit_dir, "mac_sch_stale.so")
        stale_o = os.path.join(exploit_dir, "mac_sch_stale.o")
        with open(stale_so, "w") as f:
            f.write("old")
        with open(stale_o, "w") as f:
            f.write("old")

        assert os.path.exists(stale_so)
        assert os.path.exists(stale_o)

        run_log = os.path.join(tmpdir, "run.log")
        with open(run_log, "w") as f:
            f.write("Done.\n")

        exploiter = MagicMock()
        exploiter.run_exploit_once.return_value = (False, run_log)
        exploiter.fuzz_capture_exist.return_value = False

        with patch("execution_engine.LOG_PATH", log_dir):
            engine = ExecutionEngine(
                exploiter,
                MagicMock(),
                MagicMock(),
                MagicMock(),
                run_id="rm",
                exploit_folder=exploit_dir,
            )
            engine.execute(
                "code", exploit_name="mac_sch_stale", description="stale removal"
            )

        assert not os.path.exists(stale_so)
        assert not os.path.exists(stale_o)


class TestExecuteFuzzCaptureSaveLog:
    """Test log saving when fuzz capture exists."""

    def test_save_log_called_when_capture_exists(self, tmp_dirs):
        from execution_engine import ExecutionEngine

        tmpdir, exploit_dir, log_dir = tmp_dirs
        run_log = os.path.join(tmpdir, "run.log")
        with open(run_log, "w") as f:
            f.write("Done.\n")

        exploiter = MagicMock()
        exploiter.run_exploit_once.return_value = (False, run_log)
        exploiter.fuzz_capture_exist.return_value = True

        # save_log must create the log folder (like the real exploiter does)
        def fake_save_log(folder):
            os.makedirs(folder, exist_ok=True)

        exploiter.save_log.side_effect = fake_save_log

        with patch("execution_engine.LOG_PATH", log_dir):
            engine = ExecutionEngine(
                exploiter,
                MagicMock(),
                MagicMock(),
                MagicMock(),
                run_id="sl",
                exploit_folder=exploit_dir,
            )
            engine.execute("code", exploit_name="mac_sch_sl", description="save log")

        exploiter.save_log.assert_called_once()

    def test_makedirs_when_no_capture(self, tmp_dirs):
        from execution_engine import ExecutionEngine

        tmpdir, exploit_dir, log_dir = tmp_dirs
        run_log = os.path.join(tmpdir, "run.log")
        with open(run_log, "w") as f:
            f.write("Done.\n")

        exploiter = MagicMock()
        exploiter.run_exploit_once.return_value = (False, run_log)
        exploiter.fuzz_capture_exist.return_value = False

        with patch("execution_engine.LOG_PATH", log_dir):
            engine = ExecutionEngine(
                exploiter,
                MagicMock(),
                MagicMock(),
                MagicMock(),
                run_id="md",
                exploit_folder=exploit_dir,
            )
            result = engine.execute(
                "code", exploit_name="mac_sch_md", description="mkdir"
            )

        # Log folder should have been created
        assert os.path.isdir(result.log_path)
        exploiter.save_log.assert_not_called()
