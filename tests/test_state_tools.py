"""Test state machine tools (view_state_machine, diff_state_machines)."""

import json


class TestViewStateMachine:
    def test_generates_state_machine(self, wd_tool, normal_capture):
        from tools.state_tools import get_state_tools

        tools = get_state_tools(wd_tool)
        _, handler = tools["view_state_machine"]
        result = json.loads(handler({"capture_path": normal_capture}))
        assert "total_states" in result
        assert "states" in result
        assert "transitions" in result
        assert result["total_states"] > 0
        assert len(result["states"]) == result["total_states"]

    def test_has_tx_rx_states(self, wd_tool, normal_capture):
        from tools.state_tools import get_state_tools

        tools = get_state_tools(wd_tool)
        _, handler = tools["view_state_machine"]
        result = json.loads(handler({"capture_path": normal_capture}))
        states = result["states"]
        has_tx = any("TX" in s for s in states)
        has_rx = any("RX" in s for s in states)
        assert has_tx, "No TX states found"
        assert has_rx, "No RX states found"
