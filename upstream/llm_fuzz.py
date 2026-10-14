"""Local copy of the parts of llm_fuzz.py used by 5uGUE."""

import json
import logging
import os
import re

import nest_asyncio

from constants import (
    CRASH_FULLY_NOVEL,
    CRASH_NON_PUBLICLY_KNOWN,
    CRASH_PUBLICLY_KNOWN,
    FIVEG_FIELDS_DESC,
    KNOWN_CRASH_SIGNATURES,
)
from upstream.utils.packet_cap import (
    PacketSummary,
    fix_truncated_pcap,
    is_truncated_capture,
    packet_dissection_reader,
)
from upstream.utils.state_transition import StateMachine, gen_sm
from upstream.utils.wd_utils import WDissectorTool, get_wd_tool

nest_asyncio.apply()

logger = logging.getLogger(__name__)


def extract_ts(s: str) -> float:
    """Extract timestamp from a string like `[2022-06-22 22:54:46.827969] ...`."""
    import datetime
    import re as _re

    timestamp_re = _re.compile(r"^\[.*?\]")
    if len(timestamp_re.findall(s)) == 0:
        return 0
    else:
        dt = datetime.datetime.strptime(
            timestamp_re.findall(s)[0], "[%Y-%m-%d %H:%M:%S.%f]"
        )
        return dt.timestamp()


def extract_keys(d: dict, only_deepest_keys: bool = False):
    """Traverse a dictionary recursively and return all keys."""
    res = set()
    for k, v in d.items():
        if isinstance(v, dict):
            if not only_deepest_keys:
                res.add(k)
            res.update(extract_keys(v))
        elif isinstance(v, list):
            for i in v:
                if not only_deepest_keys:
                    res.add(k)
                if isinstance(i, dict):
                    res.update(extract_keys(i))
        else:
            res.add(k)
    return res


def find_longest_prefix(data: list[str]):
    shortest_word = min(data, key=len)
    res = ""
    for prefix_slice_end in range(len(shortest_word), 0, -1):
        if all(i.startswith(shortest_word[0:prefix_slice_end]) for i in data):
            res = shortest_word[0:prefix_slice_end]
            break
    if "." in res:
        return res
    else:
        return ""


def polish_field(s: str):
    return s.split(" = ")[-1]


def polish_dict(d: dict):
    if len(d) == 0:
        return
    dict_inside = False
    for k_o in list(d.keys()):
        v_o = d[k_o]
        if isinstance(v_o, dict):
            dict_inside = True
            polish_dict(d[k_o])
        else:
            d[k_o] = polish_field(v_o)

    if not dict_inside:
        prefix = find_longest_prefix(list(d.keys()))
        if prefix != "":
            new_dict = {}
            for k_o in list(d.keys()):
                v_o = d[k_o]
                new_dict[k_o.removeprefix(prefix)] = polish_field(v_o)
                del d[k_o]
            d[prefix.strip(".")] = new_dict


def polish_packet_fields(packet_fields: dict):
    res = {}
    comment = packet_fields.get("pkt_comment")
    if comment and (
        "Fuzzed" in comment["frame.comment"]["_ws.expert"]["frame.comment.expert"]
    ):
        pass

    protocol_to_remove = {
        "frame",
        "hci_h4",
        "packetlogger",
        "pkt_comment",
        "eth",
        "ip",
        "udp",
    }
    protocol_to_take_out = {"fake-field-wrapper"}

    for k, v in packet_fields.items():
        if k in protocol_to_remove:
            continue
        if len(v) == 0:
            continue
        if k in protocol_to_take_out:
            res.update(v)
        else:
            res[k] = v

    polish_dict(res)
    return res


def read_cap(
    wd_tool: WDissectorTool,
    pcap_path: str,
    extract_fuzzed_context: bool = False,
) -> tuple[list, str]:
    packet_idx = 0
    field_keys = set()
    packets = []
    fuzzed_loc = 0
    cur_loc = 0

    buf: list[tuple[PacketSummary, object, object]] = []

    if is_truncated_capture(pcap_path):
        fix_truncated_pcap(pcap_path)

    try:
        for pkt_summary, pkt, pkt_raw in packet_dissection_reader(
            pcap_path,
            include_info=True,
            include_detailed_dissection=True,
            include_raw=True,
        ):
            if pkt_raw.packet_data.startswith(b"\x00\x00\x00\x00\x0a\xfc"):
                continue

            pkt_comment = pkt_raw.options.get("opt_comment")
            if pkt_comment is not None:
                if "Fuzzed from" in pkt_comment or "Duplicated from" in pkt_comment:
                    buf.pop(0)
                if "Fuzzed from" in pkt_comment:
                    fuzzed_loc = cur_loc

            buf.append((pkt_summary, pkt, pkt_raw))
            if len(buf) < 2:
                continue
            pkt_summary, pkt, pkt_raw = buf.pop(0)
            cur_loc += 1

            field_keys.update(extract_keys(pkt))
            polished_pkt = polish_packet_fields(pkt)

            packet_idx += 1
            packet = {
                "pkt_loc": packet_idx,
                "pkt_filter": wd_tool.label_pkt(pkt_raw.packet_data),
                "pkt_state": wd_tool.pkt_state(pkt_raw.packet_data),
                "packet_info": pkt_summary["Info"],
                "pkt_fields": polished_pkt,
                "pkt_raw": pkt_raw,
            }
            packets.append(packet)
    except Exception:
        logger.error("read_cap", exc_info=True)

    # Load field descriptions from local data
    field_desc = ""
    if os.path.exists(FIVEG_FIELDS_DESC):
        with open(FIVEG_FIELDS_DESC, "r", encoding="utf8") as f:
            desc_dict = json.load(f)
        for i in field_keys:
            if i in desc_dict:
                field_desc += f"{i}: {desc_dict[i]}\n"

    if extract_fuzzed_context:
        num_context_packets = 4
        packets = packets[
            max(0, fuzzed_loc - num_context_packets) : min(
                len(packets), fuzzed_loc + num_context_packets
            )
        ]

    return packets, field_desc


class OnePlusUtils:
    def __init__(
        self,
        ref_packets_paths: list[str],
        crash_signatures_path: str | None = None,
        crash_id_field: str = "sModemReason",
        crash_id_regex: str = r"cause:(.*)",
        monitor_log: str = "monitor.1.txt",
        wd_tool: WDissectorTool | None = None,
        capture_filename: str = "capture_nr5g_gnb.pcapng",
    ) -> None:
        self.crash_id_field = crash_id_field
        self.crash_id_regex = crash_id_regex
        self.monitor_log = monitor_log
        self.default_pcap_name = capture_filename
        sigs = self._load_known_signatures(crash_signatures_path)
        self.known_signatures_public: list[str] = sigs["public"]
        self.known_signatures_non_public: list[str] = sigs["non_public"]
        self.ref_packets_paths = ref_packets_paths
        self.wd_tool = wd_tool if wd_tool is not None else get_wd_tool("fiveg", 0)
        self.prep_reference_packets()

    @staticmethod
    def _load_known_signatures(
        crash_signatures_path: str | None = None,
    ) -> dict[str, list[str]]:
        """Load known crash signatures split into public and non-public lists."""
        empty = {"public": [], "non_public": []}
        path = (
            crash_signatures_path
            if crash_signatures_path is not None
            else KNOWN_CRASH_SIGNATURES
        )
        if not os.path.exists(path):
            return empty
        try:
            with open(path, "r") as f:
                data = json.load(f)
            if isinstance(data, dict):
                return {
                    "public": data.get("public", []),
                    "non_public": data.get("non_public", []),
                }
            # Legacy flat list: treat all as non-public
            if isinstance(data, list):
                return {"public": [], "non_public": data}
            return empty
        except Exception:
            logger.warning("Could not load known crash signatures from %s", path)
            return empty

    def crash_ids_from_trace_log(self, log_path: str) -> list[tuple[str, float]]:
        identifiers = []
        with open(log_path, "r", encoding="utf8", errors="ignore") as f:
            for line in f:
                if self.crash_id_field in line:
                    ts = extract_ts(line)
                    matches = re.findall(self.crash_id_regex, line)
                    if matches:
                        identifiers.append((matches[0], ts))
        return identifiers

    def check_crash(self, log_folder: str, **_kwargs) -> tuple[list, str]:
        """Returns (crash_ids, crash_category).

        crash_category is one of the CRASH_* constants or empty string if
        no crash IDs were found.
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
        """Classify a crash ID into one of three categories.

        Returns one of: CRASH_PUBLICLY_KNOWN, CRASH_NON_PUBLICLY_KNOWN,
        or CRASH_FULLY_NOVEL.
        """
        for sig in self.known_signatures_public:
            if sig in crash_id or crash_id in sig:
                return CRASH_PUBLICLY_KNOWN
        for sig in self.known_signatures_non_public:
            if sig in crash_id or crash_id in sig:
                return CRASH_NON_PUBLICLY_KNOWN
        return CRASH_FULLY_NOVEL

    def are_crashes_equivalent(self, crash_id1: str, crash_id2: str) -> bool:
        """Compare two OnePlus 5G crash IDs for equivalence.

        Uses simple string comparison.
        """
        return crash_id1 == crash_id2


    def read_cap(
        self, pcap_path: str, extract_fuzzed_context: bool = False
    ) -> tuple[list, str]:
        return read_cap(self.wd_tool, pcap_path, extract_fuzzed_context)

    def prep_reference_packets(self):
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


def new_states_and_transitions(
    wd_tool: WDissectorTool, base_sm: StateMachine, capture_path: str
):
    new_sm = gen_sm(wd_tool, capture_path)

    new_states = []
    for state in new_sm.states:
        if state not in base_sm.states:
            new_states.append(state)

    new_transitions = []
    for new_state in new_states:
        for next_state in new_sm.states[new_state].next_states:
            new_transitions.append(f"{new_state} to {next_state}")

    for state in new_sm.states:
        if state in base_sm.states:
            for next_state in new_sm.states[state].next_states:
                if next_state not in base_sm.states[state].next_states:
                    new_transitions.append(f"{state} to {next_state}")

    return new_states, new_transitions
