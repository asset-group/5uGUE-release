import json
import logging
import os

logger = logging.getLogger(__name__)

# Module-level default capture path, set by get_packet_tools().
_default_capture: str | None = None

# Protocols whose dissectors are generated from ASN.1 (PER/BER). For these,
# WDissector's per-field byte_offset/bitmask are unreliable: ASN.1 PER fields
# are bit-packed inside enclosing containers, so the offsets reported are
# typically the offset of an ancestor element, not the leaf field. Treat
# results for these prefixes as untrusted and surface that to the agent.
_ASN1_FIELD_PREFIXES = (
    "nr-rrc.",
    "lte-rrc.",
    "rrc.",
    "nas-5gs.",
    "nas-eps.",
    "nas.",
    "s1ap.",
    "ngap.",
    "f1ap.",
    "e1ap.",
    "xnap.",
    "x2ap.",
    "nbap.",
    "rnsap.",
    "rua.",
    "ranap.",
    "pcap.",
)


def _is_asn1_field(field_name: str) -> bool:
    return any(field_name.startswith(p) for p in _ASN1_FIELD_PREFIXES)


def _find_dissected_value(pkt_fields, field_name):
    """Walk the polished pkt_fields tree to find a dissected value for field_name.

    pkt_fields has already been polish_dict-ed, so leaf keys may be the suffix
    after the longest common prefix. Match on either full name or suffix.
    """
    suffix = field_name.split(".")[-1]

    def walk(node):
        if isinstance(node, dict):
            for k, v in node.items():
                if k == field_name or k.endswith("." + field_name) or k == suffix:
                    if not isinstance(v, (dict, list)):
                        return v
                found = walk(v)
                if found is not None:
                    return found
        elif isinstance(node, list):
            for item in node:
                found = walk(item)
                if found is not None:
                    return found
        return None

    return walk(pkt_fields)


def _extract_value_at_offset(
    packet_data, fiveg_offset, byte_offset, bitmask, bitmask_offset_bits, field_size
):
    """Slice the bytes WDissector says hold the field, apply the mask, return the int."""
    data = bytes(packet_data)
    start = fiveg_offset + byte_offset
    end = start + max(field_size, 1)
    if start < 0 or end > len(data):
        return None, None
    window = data[start:end]
    raw = int.from_bytes(window, "big")
    masked = (raw & bitmask) >> bitmask_offset_bits if bitmask else raw
    return masked, window.hex()


def _resolve_capture_path(params):
    """Resolve capture_path from params, falling back to baseline if not found."""
    default = _default_capture
    if default is None:
        from constants import NORMAL_CAPTURE

        default = NORMAL_CAPTURE
    capture_path = params.get("capture_path", default)
    if not os.path.isabs(capture_path):
        capture_path = os.path.abspath(capture_path)
    if not os.path.exists(capture_path):
        raise FileNotFoundError(f"Capture path not found: {capture_path}")
    return capture_path


def get_packet_tools(wd_tool, td_utils, normal_capture: str | None = None):
    global _default_capture
    if normal_capture is not None:
        _default_capture = normal_capture
    tools = {}

    # --- list_packet_types ---
    def list_packet_types(params):
        capture_path = _resolve_capture_path(params)

        packets, _ = td_utils.read_cap(capture_path)
        # Build summary: unique (filter, state) with counts
        type_counts = {}
        for p in packets:
            key = (p["pkt_filter"], p["pkt_state"])
            if key not in type_counts:
                type_counts[key] = {
                    "filter": p["pkt_filter"],
                    "state": p["pkt_state"],
                    "info": p["packet_info"],
                    "count": 0,
                }
            type_counts[key]["count"] += 1

        rows = sorted(type_counts.values(), key=lambda x: -x["count"])
        return json.dumps(rows, indent=2)

    tools["list_packet_types"] = (
        {
            "name": "list_packet_types",
            "description": "List unique packet types from a capture file, showing filter, state, info, and count. Returns a compact summary (~20-40 rows) instead of raw packets.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "capture_path": {
                        "type": "string",
                        "description": "Absolute path to the pcapng capture file",
                    }
                },
                "required": ["capture_path"],
            },
        },
        list_packet_types,
    )

    # --- inspect_packets ---
    def inspect_packets(params):
        capture_path = _resolve_capture_path(params)

        filter_str = params.get("filter")
        start_idx = params.get("start_index", 0)
        max_count = min(params.get("max_count", 10), 10)

        packets, _ = td_utils.read_cap(capture_path)

        results = []
        for p in packets:
            if filter_str and p["pkt_filter"] != filter_str:
                continue
            if p["pkt_loc"] < start_idx:
                continue
            results.append(
                {
                    "pkt_loc": p["pkt_loc"],
                    "pkt_filter": p["pkt_filter"],
                    "pkt_state": p["pkt_state"],
                    "packet_info": p["packet_info"],
                    "pkt_fields": p["pkt_fields"],
                }
            )
            if len(results) >= max_count:
                break

        return json.dumps(results, indent=2, default=str)

    tools["inspect_packets"] = (
        {
            "name": "inspect_packets",
            "description": "Get full dissected fields for up to 10 packets matching a filter or index range. Use list_packet_types first to identify interesting filters.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "capture_path": {
                        "type": "string",
                        "description": "Absolute path to the pcapng capture file",
                    },
                    "filter": {
                        "type": "string",
                        "description": "Wireshark display filter to match packets (e.g. 'nr-rrc.c1 == 1')",
                    },
                    "start_index": {
                        "type": "integer",
                        "description": "Start from this packet index (0-based)",
                    },
                    "max_count": {
                        "type": "integer",
                        "description": "Maximum packets to return (capped at 10)",
                    },
                },
                "required": ["capture_path"],
            },
        },
        inspect_packets,
    )

    # --- get_packet_hex ---
    def get_packet_hex(params):
        capture_path = _resolve_capture_path(params)
        packet_index = params["packet_index"]

        packets, _ = td_utils.read_cap(capture_path)
        for p in packets:
            if p["pkt_loc"] == packet_index:
                raw_bytes = bytes(p["pkt_raw"].packet_data)
                hex_str = raw_bytes.hex()
                # Format as rows of 32 hex chars (16 bytes)
                formatted = "\n".join(
                    hex_str[i : i + 32] for i in range(0, len(hex_str), 32)
                )
                return f"Packet {packet_index} ({len(raw_bytes)} bytes):\n{formatted}"
        return f"Packet at index {packet_index} not found"

    tools["get_packet_hex"] = (
        {
            "name": "get_packet_hex",
            "description": "Get the raw hex bytes of a specific packet by index.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "capture_path": {
                        "type": "string",
                        "description": "Absolute path to the pcapng capture file",
                    },
                    "packet_index": {
                        "type": "integer",
                        "description": "Packet index (pkt_loc) to retrieve",
                    },
                },
                "required": ["capture_path", "packet_index"],
            },
        },
        get_packet_hex,
    )

    # --- get_field_info ---
    def get_field_info(params):
        field_name = params["field_name"]

        if _is_asn1_field(field_name):
            return json.dumps(
                {
                    "field_name": field_name,
                    "error": (
                        f"REFUSED: '{field_name}' is an ASN.1 PER-coded field. "
                        "WDissector's per-field byte_offset/bitmask for ASN.1 leaves "
                        "is unreliable — it typically points at an enclosing container, "
                        "not the bit-packed leaf. Do not request offsets for ASN.1 fields. "
                        "Locate the field by anchor-byte search via `get_packet_hex` + "
                        "`inspect_packets` and diff against a reference packet instead."
                    ),
                }
            )

        capture_path = _resolve_capture_path(params)
        packet_filter = params.get("packet_filter")

        packets, _ = td_utils.read_cap(capture_path)

        wd_tool_protocol = getattr(wd_tool, "protocol", None)
        if wd_tool_protocol is None:
            fiveg_offset = 0
        elif wd_tool_protocol == "fiveg":
            fiveg_offset = 48
        elif wd_tool_protocol == "bt":
            fiveg_offset = 4

        last_error = None
        tried = 0
        for p in packets:
            if packet_filter and p["pkt_filter"] != packet_filter:
                continue
            tried += 1
            try:
                bitmask, bitmask_offset, field_offset, field_size = (
                    wd_tool.field_offset_bitmask(p["pkt_raw"].packet_data, field_name)
                )
            except Exception as e:
                last_error = e
                if tried >= 5:
                    break
                continue

            extracted, hex_window = _extract_value_at_offset(
                p["pkt_raw"].packet_data,
                fiveg_offset,
                field_offset,
                bitmask,
                bitmask_offset,
                field_size,
            )
            dissected = _find_dissected_value(p.get("pkt_fields", {}), field_name)

            response = {
                "field_name": field_name,
                "byte_offset": field_offset,
                "bitmask": hex(bitmask),
                "bitmask_offset_bits": bitmask_offset,
                "field_size_bytes": field_size,
                "bytes_at_offset_hex": hex_window,
                "decoded_value_at_offset": extracted,
                "dissected_value": dissected,
                "note": "Offset is relative to packet data after 48-byte 5G header",
            }

            return json.dumps(response)

        if tried == 0:
            return f"No packet found matching filter '{packet_filter}'"
        return f"Error getting field info for '{field_name}': {last_error}"

    tools["get_field_info"] = (
        {
            "name": "get_field_info",
            "description": (
                "Get byte offset, bitmask, and size of a named protocol field, plus a "
                "verification window (bytes_at_offset_hex, decoded_value_at_offset, "
                "dissected_value). REFUSED for ASN.1 PER-coded protocols (nr-rrc.*, "
                "lte-rrc.*, nas-5gs.*, ngap.*, s1ap.*, f1ap.*, etc.) — for those, use "
                "`get_packet_hex` + `inspect_packets` and anchor-byte search instead."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "capture_path": {
                        "type": "string",
                        "description": "Absolute path to the pcapng capture file",
                    },
                    "field_name": {
                        "type": "string",
                        "description": "Wireshark field name (e.g. 'mac-nr.rnti', 'nr-rrc.spare_bit')",
                    },
                    "packet_filter": {
                        "type": "string",
                        "description": "Filter to select which packet to inspect (e.g. 'rlc-nr.am.cpt == 0')",
                    },
                },
                "required": ["capture_path", "field_name"],
            },
        },
        get_field_info,
    )

    return tools
