"""Test packet analysis tools (list_packet_types, inspect_packets, get_field_info, get_packet_hex)."""

import json

import pytest


class TestListPacketTypes:
    def test_returns_valid_json(self, td_utils, normal_capture):
        from tools.packet_tools import get_packet_tools

        tools = get_packet_tools(None, td_utils)
        _, handler = tools["list_packet_types"]
        result = json.loads(handler({"capture_path": normal_capture}))
        assert isinstance(result, list)
        assert len(result) > 0

    def test_entries_have_required_fields(self, td_utils, normal_capture):
        from tools.packet_tools import get_packet_tools

        tools = get_packet_tools(None, td_utils)
        _, handler = tools["list_packet_types"]
        result = json.loads(handler({"capture_path": normal_capture}))
        for entry in result:
            assert "filter" in entry
            assert "state" in entry
            assert "count" in entry
            assert entry["count"] > 0

    def test_has_tx_and_rx_packets(self, td_utils, normal_capture):
        from tools.packet_tools import get_packet_tools

        tools = get_packet_tools(None, td_utils)
        _, handler = tools["list_packet_types"]
        result = json.loads(handler({"capture_path": normal_capture}))
        states = [e["state"] for e in result]
        has_tx = any("TX" in s for s in states)
        has_rx = any("RX" in s for s in states)
        assert has_tx, "No TX packets found in baseline capture"
        assert has_rx, "No RX packets found in baseline capture"

    def test_bad_path_raises(self, td_utils):
        from tools.packet_tools import get_packet_tools

        tools = get_packet_tools(None, td_utils)
        _, handler = tools["list_packet_types"]
        with pytest.raises(Exception):
            handler({"capture_path": "/nonexistent/file.pcapng"})


class TestInspectPackets:
    def test_returns_packets(self, wd_tool, td_utils, normal_capture):
        from tools.packet_tools import get_packet_tools

        tools = get_packet_tools(wd_tool, td_utils)
        _, handler = tools["inspect_packets"]
        result = json.loads(handler({"capture_path": normal_capture, "max_count": 3}))
        assert isinstance(result, list)
        assert 1 <= len(result) <= 3

    def test_packet_has_fields(self, wd_tool, td_utils, normal_capture):
        from tools.packet_tools import get_packet_tools

        tools = get_packet_tools(wd_tool, td_utils)
        _, handler = tools["inspect_packets"]
        result = json.loads(handler({"capture_path": normal_capture, "max_count": 1}))
        pkt = result[0]
        assert "pkt_loc" in pkt
        assert "pkt_filter" in pkt
        assert "pkt_state" in pkt
        assert "pkt_fields" in pkt

    def test_filter_narrows_results(self, wd_tool, td_utils, normal_capture):
        from tools.packet_tools import get_packet_tools

        tools = get_packet_tools(wd_tool, td_utils)
        _, handler = tools["inspect_packets"]
        # Get all types first to find a valid filter
        _, list_handler = tools["list_packet_types"]
        types = json.loads(list_handler({"capture_path": normal_capture}))
        a_filter = types[0]["filter"]

        result = json.loads(
            handler(
                {
                    "capture_path": normal_capture,
                    "filter": a_filter,
                    "max_count": 5,
                }
            )
        )
        assert all(p["pkt_filter"] == a_filter for p in result)


class TestGetPacketHex:
    def test_returns_hex_string(self, wd_tool, td_utils, normal_capture):
        from tools.packet_tools import get_packet_tools

        tools = get_packet_tools(wd_tool, td_utils)
        _, handler = tools["get_packet_hex"]
        result = handler({"capture_path": normal_capture, "packet_index": 1})
        assert "bytes" in result
        # Should contain hex chars
        assert any(c in result for c in "0123456789abcdef")


class TestGetFieldInfo:
    def test_known_field(self, wd_tool, td_utils, normal_capture):
        from tools.packet_tools import get_packet_tools

        tools = get_packet_tools(wd_tool, td_utils)
        _, handler = tools["get_field_info"]
        result = json.loads(
            handler(
                {
                    "capture_path": normal_capture,
                    "field_name": "mac-nr.rnti",
                }
            )
        )
        assert "byte_offset" in result
        assert "bitmask" in result
        assert "field_size_bytes" in result

    def test_invalid_field_returns_error(self, wd_tool, td_utils, normal_capture):
        from tools.packet_tools import get_packet_tools

        tools = get_packet_tools(wd_tool, td_utils)
        _, handler = tools["get_field_info"]
        result = handler(
            {
                "capture_path": normal_capture,
                "field_name": "nonexistent.field.name",
            }
        )
        assert "Error" in result or "error" in result

    def test_asn1_field_refused(self, wd_tool, td_utils, normal_capture):
        from tools.packet_tools import get_packet_tools

        tools = get_packet_tools(wd_tool, td_utils)
        _, handler = tools["get_field_info"]
        result = json.loads(
            handler(
                {
                    "capture_path": normal_capture,
                    "field_name": "nr-rrc.spare_bit",
                }
            )
        )
        assert "error" in result
        assert result["field_name"] == "nr-rrc.spare_bit"
        for forbidden in (
            "byte_offset",
            "bitmask",
            "bitmask_offset_bits",
            "field_size_bytes",
            "bytes_at_offset_hex",
            "decoded_value_at_offset",
            "dissected_value",
        ):
            assert forbidden not in result, (
                f"ASN.1 refusal must not expose {forbidden!r}"
            )

    def test_asn1_field_does_not_touch_capture_or_wdissector(self):
        from tools.packet_tools import get_packet_tools

        class FakeTdUtils:
            def read_cap(self, *a, **kw):
                raise AssertionError("read_cap must not be called for ASN.1")

        class FakeWdTool:
            protocol = "fiveg"

            def field_offset_bitmask(self, *a, **kw):
                raise AssertionError(
                    "field_offset_bitmask must not be called for ASN.1"
                )

        tools = get_packet_tools(FakeWdTool(), FakeTdUtils())
        _, handler = tools["get_field_info"]
        result = json.loads(
            handler(
                {
                    "capture_path": "/definitely/does/not/exist.pcapng",
                    "field_name": "lte-rrc.someLeaf",
                }
            )
        )
        assert "error" in result
        assert result["field_name"] == "lte-rrc.someLeaf"
