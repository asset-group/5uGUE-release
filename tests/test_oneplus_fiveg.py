"""Tests for oracle classes in upstream/exploiter/oneplus_fiveg.py."""

import threading
import time
from unittest.mock import MagicMock, patch

import pytest

from upstream.exploiter.oracle import (
    CrashOracle,
    DowngradeOracle,
    Oracle,
    TimeoutOracle,
)

# ---------------------------------------------------------------------------
# Oracle (base class)
# ---------------------------------------------------------------------------


class TestOracle:
    """Oracle is a plain marker base class — test that subclasses are recognised."""

    def test_oracle_is_base_of_timeout_oracle(self):
        assert issubclass(TimeoutOracle, Oracle)

    def test_oracle_is_base_of_crash_oracle(self):
        assert issubclass(CrashOracle, Oracle)

    def test_oracle_is_base_of_adb_oracle(self):
        assert issubclass(DowngradeOracle, Oracle)

    def test_oracle_instantiates(self):
        o = Oracle()
        assert isinstance(o, Oracle)


# ---------------------------------------------------------------------------
# TimeoutOracle
# ---------------------------------------------------------------------------


class TestTimeoutOracle:
    """Unit tests for TimeoutOracle."""

    def test_init_stores_timeout(self):
        oracle = TimeoutOracle(timeout=30)
        assert oracle.timeout == 30

    def test_init_sets_start_time_close_to_now(self):
        before = time.time()
        oracle = TimeoutOracle(timeout=10)
        after = time.time()
        assert before <= oracle.start_time <= after

    def test_not_timed_out_immediately(self):
        oracle = TimeoutOracle(timeout=60)
        assert oracle.is_timeout() is False

    def test_not_timed_out_before_expiry(self):
        oracle = TimeoutOracle(timeout=5)
        assert oracle.is_timeout() is False

    def test_timed_out_after_expiry(self):
        oracle = TimeoutOracle(timeout=1)
        # Back-date start_time so the timeout has already passed
        oracle.start_time = time.time() - 2
        assert oracle.is_timeout() is True

    def test_timeout_zero_is_already_expired(self):
        """A timeout of 0 should be considered expired straight away."""
        oracle = TimeoutOracle(timeout=0)
        oracle.start_time = time.time() - 0.001
        assert oracle.is_timeout() is True

    def test_is_timeout_returns_bool(self):
        oracle = TimeoutOracle(timeout=10)
        result = oracle.is_timeout()
        assert isinstance(result, bool)

    def test_is_instance_of_oracle(self):
        oracle = TimeoutOracle(timeout=5)
        assert isinstance(oracle, Oracle)

    def test_elapsed_boundary_just_before_timeout(self):
        oracle = TimeoutOracle(timeout=5)
        oracle.start_time = time.time() - 4.999
        assert oracle.is_timeout() is False

    def test_elapsed_boundary_just_after_timeout(self):
        oracle = TimeoutOracle(timeout=5)
        oracle.start_time = time.time() - 5.001
        assert oracle.is_timeout() is True


# ---------------------------------------------------------------------------
# CrashOracle
# ---------------------------------------------------------------------------


class TestCrashOracle:
    """Unit tests for CrashOracle.

    Every test creates a real temporary log file so we exercise the actual
    file-reading thread without faking the filesystem.
    """

    @staticmethod
    def _append_to_log(path: str, text: str, delay: float = 0.05):
        """Append *text* to the log after *delay* seconds (runs in a thread)."""

        def _worker():
            time.sleep(delay)
            with open(path, "a", encoding="utf8") as f:
                f.write(text)

        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        return t

    # ------------------------------------------------------------------
    # initialization
    # ------------------------------------------------------------------

    def test_init_stores_log_path(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text("")
        oracle = CrashOracle(str(log))
        try:
            assert oracle.log_path == str(log)
        finally:
            oracle.stop()

    def test_initial_state_no_crash(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text("")
        oracle = CrashOracle(str(log))
        try:
            assert oracle.crash_detected is False
        finally:
            oracle.stop()

    def test_initial_state_no_compile_error(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text("")
        oracle = CrashOracle(str(log))
        try:
            assert oracle.compile_error is False
        finally:
            oracle.stop()

    def test_initial_state_reading_log_true(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text("")
        oracle = CrashOracle(str(log))
        try:
            assert oracle.reading_log is True
        finally:
            oracle.stop()

    def test_is_instance_of_oracle(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text("")
        oracle = CrashOracle(str(log))
        try:
            assert isinstance(oracle, Oracle)
        finally:
            oracle.stop()

    def test_read_log_thread_is_daemon(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text("")
        oracle = CrashOracle(str(log))
        try:
            assert oracle.read_log_thread.daemon is True
        finally:
            oracle.stop()

    def test_read_log_thread_is_alive(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text("")
        oracle = CrashOracle(str(log))
        try:
            assert oracle.read_log_thread.is_alive()
        finally:
            oracle.stop()

    # ------------------------------------------------------------------
    # crash detection
    # ------------------------------------------------------------------

    def test_detects_crash_marker(self, tmp_path):
        """Writing [Crash] to the log should set crash_detected within a few seconds."""
        log = tmp_path / "test.log"
        log.write_text("")
        oracle = CrashOracle(str(log))
        try:
            self._append_to_log(str(log), "\n[Crash] modem crashed\n", delay=0.1)
            # Poll for up to 6 s (crash oracle sleeps 4 s after detecting)
            deadline = time.time() + 6
            while time.time() < deadline:
                if oracle.crash_happens():
                    break
                time.sleep(0.1)
            assert oracle.crash_happens() is True
        finally:
            oracle.reading_log = False  # unblock join without waiting 4 s

    def test_crash_happens_returns_false_without_marker(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text("Normal log line\nAnother line\n")
        oracle = CrashOracle(str(log))
        time.sleep(0.2)
        try:
            assert oracle.crash_happens() is False
        finally:
            oracle.stop()

    # ------------------------------------------------------------------
    # compile-error detection
    # ------------------------------------------------------------------

    def test_detects_c_module_compile_error(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text("")
        oracle = CrashOracle(str(log))
        try:
            self._append_to_log(
                str(log),
                "\nError when loading or compiling C Modules\n",
                delay=0.1,
            )
            deadline = time.time() + 3
            while time.time() < deadline:
                if oracle.is_compile_error():
                    break
                time.sleep(0.1)
            assert oracle.is_compile_error() is True
        finally:
            oracle.reading_log = False

    def test_detects_select_exploits_compile_error(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text("")
        oracle = CrashOracle(str(log))
        try:
            self._append_to_log(
                str(log),
                "\nSelect only the available exploits below\n",
                delay=0.1,
            )
            deadline = time.time() + 3
            while time.time() < deadline:
                if oracle.is_compile_error():
                    break
                time.sleep(0.1)
            assert oracle.is_compile_error() is True
        finally:
            oracle.reading_log = False

    def test_no_compile_error_for_normal_output(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text("All modules loaded successfully\nRunning exploit\n")
        oracle = CrashOracle(str(log))
        time.sleep(0.2)
        try:
            assert oracle.is_compile_error() is False
        finally:
            oracle.stop()

    # ------------------------------------------------------------------
    # stop()
    # ------------------------------------------------------------------

    def test_stop_sets_reading_log_false(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text("")
        oracle = CrashOracle(str(log))
        oracle.stop()
        assert oracle.reading_log is False

    def test_stop_joins_thread(self, tmp_path):
        log = tmp_path / "test.log"
        log.write_text("")
        oracle = CrashOracle(str(log))
        oracle.stop()
        assert not oracle.read_log_thread.is_alive()

    def test_crash_and_compile_error_are_mutually_exclusive(self, tmp_path):
        """[Crash] and compile-error are handled in the same thread loop;
        whichever arrives first wins and the thread exits."""
        log = tmp_path / "test.log"
        log.write_text("")
        oracle = CrashOracle(str(log))
        try:
            self._append_to_log(str(log), "\n[Crash] panic\n", delay=0.1)
            deadline = time.time() + 6
            while time.time() < deadline:
                if oracle.crash_happens() or oracle.is_compile_error():
                    break
                time.sleep(0.1)
            assert oracle.crash_happens() or oracle.is_compile_error()
        finally:
            oracle.reading_log = False


# ---------------------------------------------------------------------------
# ADBOracle
# ---------------------------------------------------------------------------


class TestADBOracle:
    """Unit tests for ADBOracle.

    ADBOracle.is_downgrade() calls `adb shell getprop gsm.network.type` via
    subprocess, so we mock subprocess.Popen to stay hermetic.
    """

    def _make_popen(self, output: str) -> MagicMock:
        """Return a mock Popen whose stdout yields *output*."""
        mock_process = MagicMock()
        mock_process.stdout.read.return_value = output
        mock_process.stdout.close.return_value = None
        mock_process.wait.return_value = 0
        return mock_process

    # ------------------------------------------------------------------
    # initialisation
    # ------------------------------------------------------------------

    def test_init_creates_instance(self):
        oracle = DowngradeOracle()
        assert isinstance(oracle, DowngradeOracle)

    def test_is_instance_of_oracle(self):
        oracle = DowngradeOracle()
        assert isinstance(oracle, Oracle)

    # ------------------------------------------------------------------
    # is_downgrade — downgrade path (LTE in result)
    # ------------------------------------------------------------------

    @patch("upstream.exploiter.oneplus_fiveg.subprocess.Popen")
    def test_is_downgrade_returns_true_when_lte(self, mock_popen):
        mock_popen.return_value = self._make_popen("LTE")
        oracle = DowngradeOracle()
        assert oracle.is_downgrade() is True

    @patch("upstream.exploiter.oneplus_fiveg.subprocess.Popen")
    def test_is_downgrade_true_lte_with_extra_text(self, mock_popen):
        mock_popen.return_value = self._make_popen("LTE,LTE")
        oracle = DowngradeOracle()
        assert oracle.is_downgrade() is True

    @patch("upstream.exploiter.oneplus_fiveg.subprocess.Popen")
    def test_is_downgrade_true_mixed_rat_containing_lte(self, mock_popen):
        mock_popen.return_value = self._make_popen("NR_LTE")
        oracle = DowngradeOracle()
        assert oracle.is_downgrade() is True

    # ------------------------------------------------------------------
    # is_downgrade — no downgrade path (NR / 5G / empty / unknown)
    # ------------------------------------------------------------------

    @patch("upstream.exploiter.oneplus_fiveg.subprocess.Popen")
    def test_is_downgrade_returns_false_when_nr(self, mock_popen):
        mock_popen.return_value = self._make_popen("NR")
        oracle = DowngradeOracle()
        assert oracle.is_downgrade() is False

    @patch("upstream.exploiter.oneplus_fiveg.subprocess.Popen")
    def test_is_downgrade_returns_false_when_empty(self, mock_popen):
        mock_popen.return_value = self._make_popen("")
        oracle = DowngradeOracle()
        assert oracle.is_downgrade() is False

    @patch("upstream.exploiter.oneplus_fiveg.subprocess.Popen")
    def test_is_downgrade_returns_false_when_5g_nr(self, mock_popen):
        mock_popen.return_value = self._make_popen("5G NR")
        oracle = DowngradeOracle()
        assert oracle.is_downgrade() is False

    @patch("upstream.exploiter.oneplus_fiveg.subprocess.Popen")
    def test_is_downgrade_returns_false_when_unknown(self, mock_popen):
        mock_popen.return_value = self._make_popen("UNKNOWN")
        oracle = DowngradeOracle()
        assert oracle.is_downgrade() is False

    # ------------------------------------------------------------------
    # is_downgrade — Popen call details
    # ------------------------------------------------------------------

    @patch("upstream.exploiter.oneplus_fiveg.subprocess.Popen")
    def test_is_downgrade_calls_popen_with_adb_command(self, mock_popen):
        mock_popen.return_value = self._make_popen("NR")
        oracle = DowngradeOracle()
        oracle.is_downgrade()
        call_args = mock_popen.call_args
        assert "adb shell getprop gsm.network.type" in call_args[0][0]

    @patch("upstream.exploiter.oneplus_fiveg.subprocess.Popen")
    def test_is_downgrade_uses_shell_true(self, mock_popen):
        mock_popen.return_value = self._make_popen("NR")
        oracle = DowngradeOracle()
        oracle.is_downgrade()
        assert mock_popen.call_args[1].get("shell") is True

    @patch("upstream.exploiter.oneplus_fiveg.subprocess.Popen")
    def test_is_downgrade_closes_stdout(self, mock_popen):
        mock_popen.return_value = self._make_popen("NR")
        oracle = DowngradeOracle()
        oracle.is_downgrade()
        mock_popen.return_value.stdout.close.assert_called_once()

    @patch("upstream.exploiter.oneplus_fiveg.subprocess.Popen")
    def test_is_downgrade_waits_for_process(self, mock_popen):
        mock_popen.return_value = self._make_popen("NR")
        oracle = DowngradeOracle()
        oracle.is_downgrade()
        mock_popen.return_value.wait.assert_called_once()

    @patch("upstream.exploiter.oneplus_fiveg.subprocess.Popen")
    def test_is_downgrade_returns_bool_type(self, mock_popen):
        mock_popen.return_value = self._make_popen("LTE")
        oracle = DowngradeOracle()
        result = oracle.is_downgrade()
        assert isinstance(result, bool)


class TestOnePlus5GExploiterLteBs:
    """Verify conditional execution of start_core_and_enb and stop_core_and_4g based on ENABLE_LTE_BS."""

    def test_init_sets_process_handles_to_none(self):
        from upstream.exploiter.oneplus_fiveg import OnePlus5GExploiter

        exploiter = OnePlus5GExploiter(
            run_dir="/tmp",
            modem_timeout=10,
            exploit_timeout=10,
            timeout_exploit_timeout=10,
            wd_tool=MagicMock(),
        )
        assert exploiter.open5gs_p is None
        assert exploiter.enb_p is None

    def test_stop_core_and_4g_safe_when_none(self):
        from upstream.exploiter.oneplus_fiveg import OnePlus5GExploiter

        exploiter = OnePlus5GExploiter(
            run_dir="/tmp",
            modem_timeout=10,
            exploit_timeout=10,
            timeout_exploit_timeout=10,
            wd_tool=MagicMock(),
        )
        with patch("upstream.exploiter.oneplus_fiveg.clean_up_process"):
            # Should not raise AttributeError
            exploiter.stop_core_and_4g()

    @patch("upstream.exploiter.oneplus_fiveg.clean_up_process")
    @patch("upstream.exploiter.oneplus_fiveg.subprocess.Popen")
    @patch("upstream.exploiter.oneplus_fiveg.subprocess.run")
    @patch("upstream.exploiter.oneplus_fiveg.shutil.rmtree")
    @patch("upstream.exploiter.oneplus_fiveg.os.chdir")
    @patch("upstream.exploiter.oneplus_fiveg.os.killpg")
    @patch("upstream.exploiter.oneplus_fiveg.TimeoutOracle")
    def test_run_exploit_once_bypasses_start_stop_when_lte_bs_false(
        self, mock_timeout_cls, mock_killpg, mock_chdir, mock_rmtree, mock_sub_run, mock_popen, mock_cleanup
    ):
        from upstream.exploiter.oneplus_fiveg import OnePlus5GExploiter

        mock_timeout = MagicMock()
        mock_timeout.is_timeout.side_effect = [True]
        mock_timeout_cls.return_value = mock_timeout

        mock_process = MagicMock()
        mock_process.pid = 1234
        mock_popen.return_value = mock_process

        exploiter = OnePlus5GExploiter(
            run_dir="/tmp",
            modem_timeout=10,
            exploit_timeout=10,
            timeout_exploit_timeout=10,
            wd_tool=MagicMock(),
        )
        exploiter.start_core_and_enb = MagicMock()
        exploiter.stop_core_and_4g = MagicMock()

        with patch("constants.ENABLE_LTE_BS", False):
            with patch("upstream.exploiter.oneplus_fiveg.CrashOracle"):
                exploiter.run_exploit_once("test_exploit")

        exploiter.start_core_and_enb.assert_not_called()
        exploiter.stop_core_and_4g.assert_not_called()

    @patch("upstream.exploiter.oneplus_fiveg.clean_up_process")
    @patch("upstream.exploiter.oneplus_fiveg.subprocess.Popen")
    @patch("upstream.exploiter.oneplus_fiveg.subprocess.run")
    @patch("upstream.exploiter.oneplus_fiveg.shutil.rmtree")
    @patch("upstream.exploiter.oneplus_fiveg.os.chdir")
    @patch("upstream.exploiter.oneplus_fiveg.os.killpg")
    @patch("upstream.exploiter.oneplus_fiveg.TimeoutOracle")
    def test_run_exploit_once_calls_start_stop_when_lte_bs_true(
        self, mock_timeout_cls, mock_killpg, mock_chdir, mock_rmtree, mock_sub_run, mock_popen, mock_cleanup
    ):
        from upstream.exploiter.oneplus_fiveg import OnePlus5GExploiter

        mock_timeout = MagicMock()
        mock_timeout.is_timeout.side_effect = [True]
        mock_timeout_cls.return_value = mock_timeout

        mock_process = MagicMock()
        mock_process.pid = 1234
        mock_popen.return_value = mock_process

        exploiter = OnePlus5GExploiter(
            run_dir="/tmp",
            modem_timeout=10,
            exploit_timeout=10,
            timeout_exploit_timeout=10,
            wd_tool=MagicMock(),
        )
        exploiter.start_core_and_enb = MagicMock()
        exploiter.stop_core_and_4g = MagicMock()

        with patch("constants.ENABLE_LTE_BS", True):
            with patch("upstream.exploiter.oneplus_fiveg.CrashOracle"):
                exploiter.run_exploit_once("test_exploit")

        exploiter.start_core_and_enb.assert_called_once()
        exploiter.stop_core_and_4g.assert_called_once()


