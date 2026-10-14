"""Test upstream utility modules (misc, packet_cap, state_transition, llm_fuzz)."""

import pytest


class TestMiscUtils:
    def test_calc_bytes_sha256(self):
        from upstream.utils.misc import calc_bytes_sha256

        h = calc_bytes_sha256(b"hello")
        assert isinstance(h, str)
        assert len(h) == 64  # SHA256 hex digest length

    def test_calc_bytes_sha256_deterministic(self):
        from upstream.utils.misc import calc_bytes_sha256

        assert calc_bytes_sha256(b"test") == calc_bytes_sha256(b"test")

    def test_bytes_to_cpp_array(self):
        from upstream.utils.misc import bytes_to_cpp_array

        result = bytes_to_cpp_array(b"\x00\xff")
        assert "0x0" in result
        assert "0xff" in result
        assert result.startswith("{")
        assert result.endswith("}")


class TestPacketCap:
    def test_pcap_pkt_reader(self, normal_capture):
        from upstream.utils.packet_cap import pcap_pkt_reader

        packets = list(pcap_pkt_reader(normal_capture))
        assert len(packets) > 10, f"Only {len(packets)} packets read"

    def test_packet_dissection_reader_info_and_raw(self, normal_capture):
        from upstream.utils.packet_cap import packet_dissection_reader

        count = 0
        for info, raw_pkt in packet_dissection_reader(
            normal_capture,
            include_info=True,
            include_detailed_dissection=False,
            include_raw=True,
        ):
            assert "Info" in info
            assert hasattr(raw_pkt, "packet_data")
            assert len(raw_pkt.packet_data) > 0
            count += 1
            if count >= 5:
                break
        assert count == 5


class TestStateMachine:
    def test_state_machine_basic(self):
        from upstream.utils.state_transition import StateMachine

        sm = StateMachine()
        sm.add_transition("A", "B")
        sm.add_transition("B", "C")
        assert len(sm.states) == 3
        assert "B" in sm.states["A"].next_states

    def test_gen_sm(self, wd_tool, normal_capture):
        from upstream.utils.state_transition import gen_sm

        sm = gen_sm(wd_tool, normal_capture)
        assert len(sm.states) > 3, f"Only {len(sm.states)} states generated"


class TestWDissectorToolPacketOps:
    def test_label_pkt(self, wd_tool, normal_capture):
        from upstream.utils.packet_cap import pcap_pkt_reader

        for pkt in pcap_pkt_reader(normal_capture):
            label = wd_tool.label_pkt(pkt.packet_data)
            assert isinstance(label, str)
            if label:
                assert "==" in label  # e.g. "nr-rrc.c1 == 1"
                break

    def test_pkt_state(self, wd_tool, normal_capture):
        from upstream.utils.packet_cap import pcap_pkt_reader

        for pkt in pcap_pkt_reader(normal_capture):
            state = wd_tool.pkt_state(pkt.packet_data)
            assert isinstance(state, str)
            assert len(state) > 0
            break

    def test_field_offset_bitmask(self, wd_tool, td_utils):
        """field_offset_bitmask should return valid offset/bitmask for known fields."""
        if not td_utils.ref_packets:
            pytest.skip("No reference packets available")
        # Find a packet that has mac-nr.rnti (RA-RNTI packets have it)
        for pkt_filter, pkt_data in td_utils.ref_packets.items():
            try:
                bitmask, bitmask_offset, offset, size = wd_tool.field_offset_bitmask(
                    pkt_data, "mac-nr.rnti"
                )
                if size > 0:
                    assert isinstance(bitmask, int)
                    return
            except Exception:
                continue
        # If no packet has the field, test a field we know exists: nr-rrc.c1
        for pkt_filter, pkt_data in td_utils.ref_packets.items():
            if "nr-rrc" in pkt_filter:
                bitmask, bitmask_offset, offset, size = wd_tool.field_offset_bitmask(
                    pkt_data, "nr-rrc.c1"
                )
                assert size > 0
                return
        pytest.skip("No suitable packet found for field_offset_bitmask test")


class TestOnePlusUtils:
    def test_ref_packets_loaded(self, td_utils):
        assert len(td_utils.ref_packets) > 0, "No reference packets loaded"

    def test_ref_packets_are_tx(self, td_utils, wd_tool):
        """All reference packets should be TX (base station -> UE)."""
        for pkt_filter, pkt_data in list(td_utils.ref_packets.items())[:5]:
            state = wd_tool.pkt_state(pkt_data)
            assert "TX" in state, (
                f"Non-TX packet in ref_packets: {pkt_filter} -> {state}"
            )

    def test_read_cap(self, td_utils, normal_capture):
        packets, field_desc = td_utils.read_cap(normal_capture)
        assert len(packets) > 10
        assert isinstance(field_desc, str)
        # Packets should have expected structure
        p = packets[0]
        assert "pkt_loc" in p
        assert "pkt_filter" in p
        assert "pkt_state" in p
        assert "pkt_raw" in p


class TestNewStatesAndTransitions:
    def test_same_capture(self, wd_tool, normal_capture):
        from upstream.utils.state_transition import gen_sm
        from upstream.llm_fuzz import new_states_and_transitions

        base_sm = gen_sm(wd_tool, normal_capture)
        new_s, new_t = new_states_and_transitions(wd_tool, base_sm, normal_capture)
        assert new_s == []
        assert new_t == []
