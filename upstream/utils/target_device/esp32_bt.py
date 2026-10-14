"""Target device utilities for ESP32 Bluetooth Classic targets."""

import json
import logging
import os
import re

from constants import CRASH_FULLY_NOVEL, CRASH_NON_PUBLICLY_KNOWN, CRASH_PUBLICLY_KNOWN
from upstream.llm_fuzz import extract_ts, read_cap
from upstream.utils.wd_utils import get_wd_tool

logger = logging.getLogger(__name__)


class BluetoothUtils:
    """Utilities for Bluetooth Classic target devices (e.g. ESP32).

    Responsible for:
    - Ingesting/dissecting Bluetooth pcaps
    - Initializing reference packet caches
    - Parsing device console crash logs
    - Classifying crash uniqueness based on signatures
    """

    def __init__(
        self,
        ref_packets_paths: list[str],
        crash_signatures_path: str | None = None,
        monitor_log: str = "monitor.1.txt",
        wd_tool: object | None = None,
        capture_filename: str = "capture_bluetooth.pcapng",
    ) -> None:
        self.monitor_log = monitor_log
        self.default_pcap_name = capture_filename

        # Load known crash signatures
        sigs = self._load_known_signatures(crash_signatures_path)
        self.known_signatures_public: list[str] = sigs["public"]
        self.known_signatures_non_public: list[str] = sigs["non_public"]
        self.ref_packets_paths = ref_packets_paths

        # Initialize WDissector tool for bluetooth
        self.wd_tool = wd_tool if wd_tool is not None else get_wd_tool("bt", 4)
        self.prep_reference_packets()

    @staticmethod
    def _load_known_signatures(
        crash_signatures_path: str | None = None,
    ) -> dict[str, list[str]]:
        """Load known crash signatures split into public and non-public lists."""
        empty = {"public": [], "non_public": []}
        if crash_signatures_path is None or not os.path.exists(crash_signatures_path):
            return empty
        try:
            with open(crash_signatures_path, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return {
                    "public": data.get("public", []),
                    "non_public": data.get("non_public", []),
                }
            if isinstance(data, list):
                # Legacy flat list: treat all as non-public
                return {"public": [], "non_public": data}
            return empty
        except Exception:
            logger.warning(
                "Could not load known crash signatures from %s", crash_signatures_path
            )
            return empty

    def crash_ids_from_trace_log(self, log_path: str) -> list[tuple[str, float]]:
        """Extract crash IDs and timestamps from the ESP32 trace/monitor log.

        Finds all Guru Meditation Error and Backtrace lines, grouping those
        occurring within 1 second of each other. Includes closest preceding ASSERT info.
        """
        if not os.path.exists(log_path):
            logger.warning(f"Log {log_path} does not exist.")
            return []

        identifiers = []
        timestamp_re = re.compile(r"^\[.*?\]")
        assert_re = re.compile(r".*((ASSERT|assert failed).*?(line |:)\d+).*?\n")

        guru_seen_count = 0
        assert_line: tuple[int, str] | None = None
        meaningless_line_count = 0

        with open(log_path, "r", encoding="utf8", errors="ignore") as f:
            for line_idx, line in enumerate(f):
                if "ASSERT" in line or "assert failed" in line:
                    assert_line = (line_idx, line)
                    meaningless_line_count = 0
                elif line == "\n" or "Send flooding packet now" in line:
                    meaningless_line_count += 1
                elif ("Guru Meditation Error" in line) or ("Backtrace:" in line):
                    if "Guru Meditation Error" in line:
                        guru_seen_count += 1
                    identifier = timestamp_re.sub("", line).strip()
                    timestamp = extract_ts(line)

                    # Append lines if close in time; group under single crash identifier
                    if (
                        guru_seen_count <= 1
                        and len(identifiers) > 0
                        and abs(timestamp - identifiers[-1][1]) < 1
                    ):
                        identifiers[-1][0] = identifiers[-1][0] + "|" + identifier
                    else:
                        if assert_line is None:
                            identifiers.append(["|" + identifier, timestamp])
                        else:
                            is_assert_line_close = (
                                line_idx - assert_line[0] - meaningless_line_count < 15
                            )
                            is_assert_line_close = is_assert_line_close and (
                                extract_ts(line) - extract_ts(assert_line[1]) < 2
                            )
                            if is_assert_line_close:
                                re_res = assert_re.findall(assert_line[1])
                                if len(re_res) > 0:
                                    identifiers.append(
                                        [
                                            re_res[0][0] + "|" + identifier,
                                            timestamp,
                                        ]
                                    )
                                else:
                                    identifiers.append(["|" + identifier, timestamp])
                                assert_line = None
                            else:
                                identifiers.append(["|" + identifier, timestamp])

                        guru_seen_count = 1

        return [(item[0], item[1]) for item in identifiers]

    def check_crash(self, log_folder: str, **_kwargs) -> tuple[list, str]:
        """Check for crashes in the log folder.

        Returns (crash_ids, crash_category) tuple.
        """
        device_log_path = os.path.join(log_folder, self.monitor_log)
        crash_id: list = []
        crash_category = ""
        if os.path.exists(device_log_path):
            crash_id = self.crash_ids_from_trace_log(device_log_path)
            if len(crash_id) > 0:
                crash_category = self.classify_crash(crash_id[0][0])
        else:
            logger.error(
                f"Crash happens but no device log is available: {device_log_path}"
            )
        return crash_id, crash_category

    def classify_crash(self, crash_id: str) -> str:
        """Classify a crash ID as public, non-public, or fully novel."""
        for sig in self.known_signatures_public:
            if sig in crash_id or crash_id in sig:
                return CRASH_PUBLICLY_KNOWN
        for sig in self.known_signatures_non_public:
            if sig in crash_id or crash_id in sig:
                return CRASH_NON_PUBLICLY_KNOWN
        return CRASH_FULLY_NOVEL

    def are_crashes_equivalent(self, crash_id1: str, crash_id2: str) -> bool:
        """Compare two Bluetooth crash IDs for equivalence.

        Delegates to the standalone are_bt_crashes_equivalent function.
        """
        return are_bt_crashes_equivalent(crash_id1, crash_id2)

    def read_cap(
        self, pcap_path: str, extract_fuzzed_context: bool = False
    ) -> tuple[list, str]:
        """Dissect pcap using the bluetooth protocol."""
        return read_cap(self.wd_tool, pcap_path, extract_fuzzed_context)

    def prep_reference_packets(self) -> None:
        """Cache TX packets from reference captures to use as mutation bases."""
        self.ref_packets: dict[str, bytes] = {}
        for ref_path in self.ref_packets_paths:
            ref_packets, _ = self.read_cap(ref_path)
            for p in ref_packets:
                if (
                    p["pkt_state"].startswith("TX")
                    and p["pkt_filter"] not in self.ref_packets
                ):
                    self.ref_packets[p["pkt_filter"]] = p["pkt_raw"].packet_data
        logger.debug(
            f"Load reference packets complete! Total {len(self.ref_packets)} reference packets."
        )


def are_bt_crashes_equivalent(crash_id1: str, crash_id2: str) -> bool:
    """Compare two Bluetooth crash IDs for equivalence.

    Splits each crash_id by '|' and compares their first parts (e.g. ASSERT info).
    If both first parts are non-empty and match, they are considered equivalent.
    If the first parts do not match, or if one/both are empty, compares all the
    remaining parts.
    Special exception: in the first backtrace part, the first hex value
    (e.g., hex1 in hex1:hex2) is allowed to differ.
    """
    if crash_id1 == crash_id2:
        return True
    if crash_id1 is None or crash_id2 is None:
        return False

    parts1 = [p.strip() for p in crash_id1.split("|")]
    parts2 = [p.strip() for p in crash_id2.split("|")]

    first1 = parts1[0]
    first2 = parts2[0]

    # If first parts are non-empty and match, they are equivalent
    if first1 and first2 and first1 == first2:
        return True

    # Otherwise (first parts don't match, or one/both is empty),
    # we must compare all remaining parts.
    rest1 = parts1[1:]
    rest2 = parts2[1:]

    # If there are no rest parts, and they didn't match on the first part,
    # then they cannot be equivalent.
    if not rest1 or not rest2:
        return False

    if len(rest1) != len(rest2):
        return False

    first_backtrace_seen = False
    for p1, p2 in zip(rest1, rest2):
        if p1.startswith("Backtrace:") and p2.startswith("Backtrace:"):
            if not first_backtrace_seen:
                first_backtrace_seen = True
                if not _compare_first_backtrace(p1, p2):
                    return False
            else:
                if p1 != p2:
                    return False
        else:
            if p1 != p2:
                return False

    return True


def _compare_first_backtrace(p1: str, p2: str) -> bool:
    """Compare two backtrace parts, allowing the first hex value to differ."""
    bt1 = p1[len("Backtrace:") :].strip()
    bt2 = p2[len("Backtrace:") :].strip()

    frames1 = bt1.split()
    frames2 = bt2.split()

    if len(frames1) != len(frames2):
        return False

    if not frames1:
        return True

    # Compare all frames from index 1 to the end exactly
    if frames1[1:] != frames2[1:]:
        return False

    # For the first frame (index 0), compare hex2 in hex1:hex2
    f1 = frames1[0]
    f2 = frames2[0]

    parts_f1 = f1.split(":")
    parts_f2 = f2.split(":")

    if len(parts_f1) == 2 and len(parts_f2) == 2:
        return parts_f1[1] == parts_f2[1]
    else:
        return f1 == f2
