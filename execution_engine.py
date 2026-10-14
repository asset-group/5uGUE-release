import logging
import os
import re
import signal
import subprocess
import time
from dataclasses import dataclass, field

from constants import (
    AGENT_GENERATED_CRASHES,
    AGENT_GENERATED_TESTS,
    EDITCAP_PATH,
    LOG_PATH,
    SKIP_EXPLOIT_CLEANUP,
)
from upstream.utils.misc import calc_bytes_sha256, clean_up_process

logger = logging.getLogger(__name__)


@dataclass
class TestResult:
    __test__ = False  # not a pytest test class
    test_id: str
    fuzz_description: str
    compile_success: bool
    compile_error: str | None
    execution_time_seconds: float
    crash_triggered: bool
    crash_id: str | None
    crash_category: str
    crash_summary: str | None
    exploit_name: str = ""
    exploit_code: str = ""
    new_states: list[str] = field(default_factory=list)
    new_transitions: list[str] = field(default_factory=list)
    capture_path: str = ""
    log_path: str = ""
    total_packets: int = 0
    exploit_hash: str = ""
    mutation_count: int = 0
    mutation_log_lines: list[str] = field(default_factory=list)
    mutation_parse_warnings: list[str] = field(default_factory=list)


class ExecutionEngine:
    def __init__(
        self,
        exploiter,
        td_utils,
        wd_tool,
        base_sm,
        run_id: str = "0000",
        exploit_folder: str | None = None,
        capture_filename: str = "capture_nr5g_gnb.pcapng",
        profile=None,
    ):
        self.exploiter = exploiter
        self.td_utils = td_utils
        self.wd_tool = wd_tool
        self.base_sm = base_sm
        self.run_id = run_id
        self.test_count = 0
        if exploit_folder is None:
            from constants import EXPLOIT_FOLDER

            exploit_folder = EXPLOIT_FOLDER
        self.exploit_folder = exploit_folder
        self.capture_filename = capture_filename
        self.profile = profile
        self._session_exploits = set()  # track agent-created files in exploit_folder

    def _cleanup_session_exploits(self):
        """Hard-reset exploit folder: remove all .cpp/.so/.o except ModulesStub.o."""
        keep_base = {"ModulesStub"}
        for fname in os.listdir(self.exploit_folder):
            fpath = os.path.join(self.exploit_folder, fname)
            if not os.path.isfile(fpath):
                continue
            base, ext = os.path.splitext(fname)
            if ext in (".cpp", ".so", ".o") and base not in keep_base:
                try:
                    os.remove(fpath)
                except OSError:
                    pass
        self._session_exploits.clear()

    @staticmethod
    def _fix_truncated_pcap(path: str) -> bool:
        """Fix truncated pcap/pcapng in-place using editcap. Returns True if file is usable."""
        try:
            size = os.path.getsize(path)
            if size == 0:
                return False
            capture_format = os.path.splitext(path)[1].removeprefix(".")
            if capture_format not in ("pcap", "pcapng"):
                return False
            result = subprocess.run(
                [EDITCAP_PATH, "-F", capture_format, path, path],
                capture_output=True,
                timeout=30,
            )
            # editcap returns 0 even for truncated files (it just drops the bad packet)
            return result.returncode == 0 and os.path.getsize(path) > 0
        except Exception:
            logger.debug("editcap repair failed", exc_info=True)
            return False

    def execute(
        self,
        exploit_code: str,
        exploit_name: str = "mac_sch_laf",
        description: str = "",
        timeout: int | None = None,
        skip_state_diff: bool = False,
    ) -> TestResult:
        self.test_count += 1
        test_id = f"{self.run_id}-{self.test_count}"
        exploit_hash = calc_bytes_sha256(exploit_code.encode())

        # Clean up any agent-generated files from previous tests
        if not SKIP_EXPLOIT_CLEANUP:
            self._cleanup_session_exploits()

        # Write exploit code to WDissector folder (required for compilation)
        exploit_path = os.path.join(self.exploit_folder, f"{exploit_name}.cpp")
        with open(exploit_path, "w", encoding="utf8") as f:
            f.write(exploit_code)
            f.flush()
        self._session_exploits.add(exploit_name)
        # Archive a copy in agent_generated_tests/
        archive_path = os.path.join(AGENT_GENERATED_TESTS, f"{exploit_name}.cpp")
        with open(archive_path, "w", encoding="utf8") as f:
            f.write(exploit_code)
        time.sleep(0.5)

        # Remove stale .so/.o to force recompile
        for ext in (".so", ".o"):
            p = os.path.join(self.exploit_folder, f"{exploit_name}{ext}")
            if os.path.exists(p):
                os.remove(p)

        # Run exploit
        start_time = time.time()
        crash_triggered, run_log_path = self.exploiter.run_exploit_once(
            exploit_name, timeout=timeout
        )
        execution_time = time.time() - start_time

        # Check for compile error
        compile_success = True
        compile_error = None
        if os.path.exists(run_log_path):
            with open(run_log_path, "r", encoding="utf8", errors="ignore") as f:
                log_content = f.read()
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

        if not compile_success:
            return TestResult(
                test_id=test_id,
                fuzz_description=description,
                compile_success=False,
                compile_error=compile_error,
                execution_time_seconds=execution_time,
                crash_triggered=False,
                crash_id=None,
                crash_category="",
                crash_summary=None,
                exploit_name=exploit_name,
                exploit_code=exploit_code,
                exploit_hash=exploit_hash,
                log_path=run_log_path,
            )

        # Parse mutation delivery metrics from run log
        mutation_count = 0
        mutation_log_lines = []
        if os.path.exists(run_log_path):
            _ansi_re = re.compile(r"\x1b\[[0-9;]*m")
            with open(run_log_path, "r", encoding="utf8", errors="ignore") as f:
                for line in f:
                    clean = _ansi_re.sub("", line)
                    # Check for LTE/5G fuzzed marker OR Bluetooth/Wi-Fi fuzzed packet containing "TX -->" and styled with magenta (ANSI color code 35)
                    is_fuzzed = "[M] TX -->" in clean or (
                        "TX -->" in clean and any("35" in code for code in re.findall(r"\x1b\[[0-9;]*m", line))
                    )
                    if is_fuzzed:
                        mutation_count += 1
                        if len(mutation_log_lines) < 10:
                            mutation_log_lines.append(clean.strip())

        # Save logs
        log_folder = os.path.join(
            LOG_PATH, f"run_{self.run_id}", f"test_{self.test_count}"
        )
        if self.exploiter.fuzz_capture_exist():
            self.exploiter.save_log(log_folder)
        else:
            os.makedirs(log_folder, exist_ok=True)

        # Save exploit source in test log folder for reproducibility
        exploit_save_path = os.path.join(log_folder, f"{exploit_name}.cpp")
        with open(exploit_save_path, "w", encoding="utf8") as f:
            f.write(exploit_code)

        # Post-timeout downgrade check: if no crash detected but exploiter
        # supports downgrade detection, check the run log for downgrade patterns
        if not crash_triggered and hasattr(self.exploiter, "detect_downgrade_attack"):
            if os.path.exists(run_log_path) and self.exploiter.detect_downgrade_attack(
                run_log_path
            ):
                logger.info("Downgrade attack detected post-timeout")
                crash_triggered = True

        # Check crash
        crash_id = None
        crash_category = ""
        crash_summary = None
        parse_warnings: list[str] = []
        if crash_triggered:
            try:
                result = self.td_utils.check_crash(
                    log_folder, exploit_code=exploit_code
                )
                # Check return tuple length (3-tuple with parse_warnings or standard 2-tuple)
                if len(result) == 3:
                    crash_ids, category, parse_warnings = result
                else:
                    crash_ids, category = result
                if crash_ids and len(crash_ids) > 0:
                    crash_id = crash_ids[0][0]
                    crash_category = category
                    monitor_filename = getattr(
                        self.td_utils, "monitor_log", "monitor.1.txt"
                    )
                    monitor_path = os.path.join(log_folder, monitor_filename)
                    if os.path.exists(monitor_path):
                        with open(
                            monitor_path, "r", encoding="utf8", errors="ignore"
                        ) as f:
                            content = f.read()
                        crash_id_field = getattr(
                            self.td_utils, "crash_id_field", "sModemReason"
                        )
                        idx = content.find(crash_id_field)
                        if idx >= 0:
                            crash_summary = content[max(0, idx - 200) : idx + 300]
                        else:
                            crash_summary = (
                                content[-500:] if len(content) > 500 else content
                            )
                elif exploit_code and hasattr(
                    self.td_utils, "classify_by_attack_vector"
                ):
                    # Downgrade attacks: no crash_ids but still classify mutations
                    crash_category, parse_warnings = (
                        self.td_utils.classify_by_attack_vector(
                            exploit_code,
                        )
                    )
            except Exception as e:
                logger.error(f"Error checking crash: {e}", exc_info=True)

        # If crash confirmed, also archive to agent_generated_crashes/
        if crash_triggered and crash_id:
            crash_archive = os.path.join(AGENT_GENERATED_CRASHES, f"{exploit_name}.cpp")
            with open(crash_archive, "w", encoding="utf8") as f:
                f.write(exploit_code)

        # State diff
        new_states = []
        new_transitions = []
        capture_path = os.path.join(log_folder, self.capture_filename)
        total_packets = 0
        if os.path.exists(capture_path) and not skip_state_diff:
            # Fix truncated pcap in-place before feeding to tshark
            pcap_valid = self._fix_truncated_pcap(capture_path)
            if not pcap_valid:
                logger.warning(
                    f"Skipping state diff & packet count: pcap unusable after repair attempt: {capture_path}"
                )
            else:
                try:
                    from upstream.llm_fuzz import new_states_and_transitions

                    new_states, new_transitions = new_states_and_transitions(
                        self.wd_tool, self.base_sm, capture_path
                    )
                except Exception as e:
                    logger.error(f"Error computing state diff: {e}", exc_info=True)
                    try:
                        clean_up_process("tshark", signal.SIGKILL)
                    except Exception:
                        pass

                # Count packets using raw pcap reader (no tshark needed)
                try:
                    from upstream.utils.packet_cap import pcap_pkt_reader

                    for _ in pcap_pkt_reader(capture_path):
                        total_packets += 1
                except Exception:
                    pass

        return TestResult(
            test_id=test_id,
            fuzz_description=description,
            compile_success=True,
            compile_error=None,
            execution_time_seconds=execution_time,
            crash_triggered=crash_triggered,
            crash_id=crash_id,
            crash_category=crash_category,
            crash_summary=crash_summary,
            exploit_name=exploit_name,
            exploit_code=exploit_code,
            new_states=new_states,
            new_transitions=new_transitions,
            capture_path=capture_path,
            log_path=log_folder,
            total_packets=total_packets,
            exploit_hash=exploit_hash,
            mutation_count=mutation_count,
            mutation_log_lines=mutation_log_lines,
            mutation_parse_warnings=parse_warnings,
        )
