"""Tests for AgentMetrics (tools/turn, crash rate, token usage)."""

import json
import os


from agent_metrics import AgentMetrics


def _log_turn_kwargs(
    m,
    turn,
    tools_called,
    input_tokens,
    output_tokens,
    cumulative_input_tokens,
    cumulative_output_tokens,
    turn_crashes=0,
    turn_publicly_known=0,
    turn_non_publicly_known=0,
    turn_fully_novel=0,
    session_unique_crash_ids=None,
    session_unique_novel_crash_ids=None,
):
    """Helper to call log_turn with new signature."""
    if session_unique_crash_ids is None:
        session_unique_crash_ids = set()
    if session_unique_novel_crash_ids is None:
        session_unique_novel_crash_ids = set()
    m.log_turn(
        turn=turn,
        tools_called=tools_called,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        cumulative_input_tokens=cumulative_input_tokens,
        cumulative_output_tokens=cumulative_output_tokens,
        turn_crashes=turn_crashes,
        turn_publicly_known=turn_publicly_known,
        turn_non_publicly_known=turn_non_publicly_known,
        turn_fully_novel=turn_fully_novel,
        session_unique_crash_ids=session_unique_crash_ids,
        session_unique_novel_crash_ids=session_unique_novel_crash_ids,
    )


class TestAgentMetrics:
    def _make_metrics(self, tmpdir):
        m = AgentMetrics(run_id="test123", log_dir=tmpdir)
        m.start()
        return m

    def test_log_turn_writes_jsonl(self, tmp_path):
        m = self._make_metrics(str(tmp_path))
        _log_turn_kwargs(
            m,
            turn=1,
            tools_called=["inspect_packets", "execute_test"],
            input_tokens=5000,
            output_tokens=800,
            cumulative_input_tokens=5000,
            cumulative_output_tokens=800,
        )
        m.stop()

        log_path = os.path.join(str(tmp_path), "agent_metrics_test123.jsonl")
        assert os.path.exists(log_path)
        with open(log_path) as f:
            lines = f.readlines()
        assert len(lines) == 1
        record = json.loads(lines[0])
        assert record["turn"] == 1
        assert record["tool_call_count"] == 2
        assert record["tools_called"] == ["inspect_packets", "execute_test"]
        assert record["input_tokens"] == 5000
        assert record["output_tokens"] == 800

    def test_cumulative_crash_counting(self, tmp_path):
        m = self._make_metrics(str(tmp_path))
        session_ids = {"CRASH_A"}
        _log_turn_kwargs(
            m,
            turn=1,
            tools_called=["execute_test"],
            input_tokens=1000,
            output_tokens=200,
            cumulative_input_tokens=1000,
            cumulative_output_tokens=200,
            turn_crashes=1,
            turn_publicly_known=1,
            session_unique_crash_ids=session_ids,
        )
        session_ids.add("CRASH_B")
        _log_turn_kwargs(
            m,
            turn=2,
            tools_called=["execute_test"],
            input_tokens=1200,
            output_tokens=300,
            cumulative_input_tokens=2200,
            cumulative_output_tokens=500,
            turn_crashes=2,
            turn_non_publicly_known=1,
            turn_fully_novel=1,
            session_unique_crash_ids=session_ids,
        )
        m.stop()

        assert m._records[0]["cumulative_crashes"] == 1
        assert m._records[0]["cumulative_publicly_known"] == 1
        assert m._records[0]["session_unique_crashes"] == 1
        assert m._records[1]["cumulative_crashes"] == 3
        assert m._records[1]["cumulative_non_publicly_known"] == 1
        assert m._records[1]["cumulative_fully_novel"] == 1
        assert m._records[1]["session_unique_crashes"] == 2

    def test_session_unique_novel_crashes_recorded(self, tmp_path):
        m = self._make_metrics(str(tmp_path))
        novel_ids = {"n1"}
        _log_turn_kwargs(
            m,
            turn=1,
            tools_called=["execute_test"],
            input_tokens=1000,
            output_tokens=200,
            cumulative_input_tokens=1000,
            cumulative_output_tokens=200,
            turn_crashes=1,
            turn_fully_novel=1,
            session_unique_crash_ids={"n1"},
            session_unique_novel_crash_ids=novel_ids,
        )
        novel_ids.add("n2")
        _log_turn_kwargs(
            m,
            turn=2,
            tools_called=["execute_test"],
            input_tokens=1200,
            output_tokens=300,
            cumulative_input_tokens=2200,
            cumulative_output_tokens=500,
            turn_crashes=1,
            turn_fully_novel=1,
            session_unique_crash_ids={"n1", "n2"},
            session_unique_novel_crash_ids=novel_ids,
        )
        m.stop()

        assert m._records[0]["session_unique_novel_crashes"] == 1
        assert m._records[1]["session_unique_novel_crashes"] == 2

    def test_session_unique_novel_defaults_to_zero(self, tmp_path):
        m = self._make_metrics(str(tmp_path))
        _log_turn_kwargs(
            m,
            turn=1,
            tools_called=["execute_test"],
            input_tokens=100,
            output_tokens=50,
            cumulative_input_tokens=100,
            cumulative_output_tokens=50,
        )
        m.stop()
        assert m._records[0]["session_unique_novel_crashes"] == 0

    def test_tool_counts_aggregation(self, tmp_path):
        m = self._make_metrics(str(tmp_path))
        _log_turn_kwargs(
            m,
            turn=1,
            tools_called=["inspect_packets", "execute_test", "inspect_packets"],
            input_tokens=0,
            output_tokens=0,
            cumulative_input_tokens=0,
            cumulative_output_tokens=0,
        )
        m.stop()

        record = m._records[0]
        assert record["tool_counts"] == {"inspect_packets": 2, "execute_test": 1}
        assert record["tool_call_count"] == 3

    def test_chart_generation(self, tmp_path):
        m = self._make_metrics(str(tmp_path))
        for i in range(1, 4):
            _log_turn_kwargs(
                m,
                turn=i,
                tools_called=["execute_test"],
                input_tokens=1000 * i,
                output_tokens=200 * i,
                cumulative_input_tokens=1000 * i,
                cumulative_output_tokens=200 * i,
                turn_crashes=i % 2,
                turn_fully_novel=i % 2,
            )
        m.stop()

        png_path = os.path.join(str(tmp_path), "agent_metrics_test123.png")
        assert os.path.exists(png_path)
        assert os.path.getsize(png_path) > 0

    def test_no_chart_with_insufficient_data(self, tmp_path):
        m = self._make_metrics(str(tmp_path))
        _log_turn_kwargs(
            m,
            turn=1,
            tools_called=["execute_test"],
            input_tokens=100,
            output_tokens=50,
            cumulative_input_tokens=100,
            cumulative_output_tokens=50,
        )
        m.stop()  # should not crash

        png_path = os.path.join(str(tmp_path), "agent_metrics_test123.png")
        assert not os.path.exists(png_path)
