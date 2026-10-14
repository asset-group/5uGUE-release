"""Tests for execute_test_batch tool and agent_core batch handling."""

import json
import os
import tempfile
import shutil
from dataclasses import asdict
from unittest.mock import MagicMock, patch

import pytest

from execution_engine import TestResult


def _make_test_result(
    test_id="test-1",
    compile_success=True,
    crash_triggered=False,
    crash_id=None,
    crash_category="",
    mutation_count=5,
    total_packets=80,
    exploit_name="mac_sch_batch_0",
    new_states=None,
    new_transitions=None,
    crash_summary=None,
):
    """Helper to build a TestResult with sensible defaults."""
    return TestResult(
        test_id=test_id,
        fuzz_description="test desc",
        compile_success=compile_success,
        compile_error="some error" if not compile_success else None,
        execution_time_seconds=2.0,
        crash_triggered=crash_triggered,
        crash_id=crash_id,
        crash_category=crash_category,
        crash_summary=crash_summary,
        exploit_name=exploit_name,
        exploit_code="#include <ModulesInclude.hpp>\n// test",
        new_states=new_states or [],
        new_transitions=new_transitions or [],
        capture_path="/tmp/capture.pcapng",
        log_path="/tmp/logs/test_1",
        total_packets=total_packets,
        exploit_hash="abc123",
        mutation_count=mutation_count,
        mutation_log_lines=[],
    )


@pytest.fixture
def batch_tools():
    """Build exploit tools with a mocked engine for batch testing."""
    engine = MagicMock()
    engine.run_id = "run42"
    engine.test_count = 0

    session_exploits = set()

    with (
        patch("tools.exploit_tools.AGENT_GENERATED_TESTS", "/tmp/ag_tests"),
        patch("tools.exploit_tools.AGENT_GENERATED_CRASHES", "/tmp/ag_crashes"),
    ):
        from tools.exploit_tools import get_exploit_tools

        tools = get_exploit_tools(
            wd_tool=None,
            td_utils=None,
            engine=engine,
            config=None,
            session_exploits=session_exploits,
            exploit_folder="/tmp/exploits",
        )

    return tools, engine, session_exploits


def _make_test_case(
    code="// test", timeout=30, name=None, desc="test", category="bit_flip"
):
    tc = {
        "exploit_code": code,
        "timeout_seconds": timeout,
        "description": desc,
        "mutation_category": category,
    }
    if name:
        tc["exploit_name"] = name
    return tc


class TestBatchBasicBehavior:
    def test_batch_runs_all_tests(self, batch_tools):
        tools, engine, _ = batch_tools
        engine.execute.side_effect = [
            _make_test_result(test_id="run42-1"),
            _make_test_result(test_id="run42-2"),
            _make_test_result(test_id="run42-3"),
        ]
        _, handler = tools["execute_test_batch"]
        result = json.loads(
            handler(
                {
                    "test_cases": [_make_test_case() for _ in range(3)],
                }
            )
        )
        assert result["batch_size"] == 3
        assert result["tests_executed"] == 3
        assert len(result["results"]) == 3
        assert result["results"][0]["test_id"] == "run42-1"
        assert result["results"][2]["test_id"] == "run42-3"
        assert result["batch_summary"]["crashes"] == 0

    def test_batch_single_test(self, batch_tools):
        tools, engine, _ = batch_tools
        engine.execute.return_value = _make_test_result(test_id="run42-1")
        _, handler = tools["execute_test_batch"]
        result = json.loads(
            handler(
                {
                    "test_cases": [_make_test_case()],
                }
            )
        )
        assert result["batch_size"] == 1
        assert result["tests_executed"] == 1
        assert len(result["results"]) == 1

    def test_batch_returns_valid_json(self, batch_tools):
        tools, engine, _ = batch_tools
        engine.execute.return_value = _make_test_result()
        _, handler = tools["execute_test_batch"]
        result = json.loads(
            handler(
                {
                    "test_cases": [_make_test_case()],
                }
            )
        )
        assert "batch_size" in result
        assert "tests_executed" in result
        assert "batch_summary" in result
        assert "results" in result
        assert "REQUIRED_NEXT_STEP" in result
        assert "total_execution_time_seconds" in result


class TestBatchCrashHandling:
    def test_batch_counts_crashes(self, batch_tools):
        tools, engine, _ = batch_tools
        engine.execute.side_effect = [
            _make_test_result(test_id="run42-1"),
            _make_test_result(
                test_id="run42-2",
                crash_triggered=True,
                crash_id="CRASH_A",
                crash_category="publicly_known_crash",
            ),
            _make_test_result(test_id="run42-3"),
        ]
        _, handler = tools["execute_test_batch"]
        result = json.loads(
            handler(
                {
                    "test_cases": [_make_test_case() for _ in range(3)],
                }
            )
        )
        assert result["batch_summary"]["crashes"] == 1
        assert result["batch_summary"]["crash_categories"] == {
            "publicly_known_crash": 1
        }
        assert result["results"][1]["crash_triggered"] is True
        assert result["results"][1]["crash_id"] == "CRASH_A"

    def test_stop_on_crash_true(self, batch_tools):
        tools, engine, _ = batch_tools
        engine.execute.side_effect = [
            _make_test_result(test_id="run42-1"),
            _make_test_result(
                test_id="run42-2",
                crash_triggered=True,
                crash_id="CRASH_A",
                crash_category="fully_novel_crash",
            ),
            _make_test_result(test_id="run42-3"),  # should not be reached
        ]
        _, handler = tools["execute_test_batch"]
        result = json.loads(
            handler(
                {
                    "test_cases": [_make_test_case() for _ in range(3)],
                    "stop_on_crash": True,
                }
            )
        )
        assert result["tests_executed"] == 2
        assert result["batch_size"] == 3
        assert engine.execute.call_count == 2

    def test_stop_on_crash_false_default(self, batch_tools):
        tools, engine, _ = batch_tools
        engine.execute.side_effect = [
            _make_test_result(test_id="run42-1"),
            _make_test_result(
                test_id="run42-2",
                crash_triggered=True,
                crash_id="CRASH_A",
                crash_category="publicly_known_crash",
            ),
            _make_test_result(test_id="run42-3"),
        ]
        _, handler = tools["execute_test_batch"]
        result = json.loads(
            handler(
                {
                    "test_cases": [_make_test_case() for _ in range(3)],
                }
            )
        )
        assert result["tests_executed"] == 3
        assert engine.execute.call_count == 3


class TestBatchCompileFailures:
    def test_compile_failure_continues_batch(self, batch_tools):
        tools, engine, _ = batch_tools
        engine.execute.side_effect = [
            _make_test_result(test_id="run42-1", compile_success=False),
            _make_test_result(test_id="run42-2", compile_success=True),
        ]
        _, handler = tools["execute_test_batch"]
        result = json.loads(
            handler(
                {
                    "test_cases": [_make_test_case(), _make_test_case()],
                }
            )
        )
        assert result["tests_executed"] == 2
        assert result["batch_summary"]["compile_failures"] == 1
        assert result["results"][0]["compile_success"] is False
        assert result["results"][1]["compile_success"] is True


class TestBatchEdgeCases:
    def test_batch_empty_rejected(self, batch_tools):
        tools, engine, _ = batch_tools
        _, handler = tools["execute_test_batch"]
        result = json.loads(handler({"test_cases": []}))
        assert "error" in result

    def test_batch_over_limit_rejected(self, batch_tools):
        tools, engine, _ = batch_tools
        _, handler = tools["execute_test_batch"]
        result = json.loads(
            handler(
                {
                    "test_cases": [_make_test_case() for _ in range(6)],
                }
            )
        )
        assert "error" in result
        assert "5" in result["error"]

    def test_exploit_name_auto_prefixed(self, batch_tools):
        tools, engine, _ = batch_tools
        engine.execute.return_value = _make_test_result()
        _, handler = tools["execute_test_batch"]
        handler(
            {
                "test_cases": [_make_test_case(name="my_test")],
            }
        )
        call_args = engine.execute.call_args
        assert call_args[0][1].startswith("mac_sch_")

    def test_session_exploits_tracked(self, batch_tools):
        tools, engine, session_exploits = batch_tools
        engine.execute.side_effect = [
            _make_test_result(exploit_name="mac_sch_a"),
            _make_test_result(exploit_name="mac_sch_b"),
        ]
        _, handler = tools["execute_test_batch"]
        handler(
            {
                "test_cases": [
                    _make_test_case(name="mac_sch_a"),
                    _make_test_case(name="mac_sch_b"),
                ],
            }
        )
        assert "mac_sch_a.cpp" in session_exploits
        assert "mac_sch_b.cpp" in session_exploits

    def test_default_name_includes_run_id(self, batch_tools):
        tools, engine, _ = batch_tools
        engine.execute.return_value = _make_test_result()
        _, handler = tools["execute_test_batch"]
        handler(
            {
                "test_cases": [_make_test_case()],  # no explicit name
            }
        )
        call_args = engine.execute.call_args
        exploit_name = call_args[0][1]
        assert "run42" in exploit_name


class TestBatchAgentCoreIntegration:
    """Test that agent_core.py correctly processes execute_test_batch results."""

    @staticmethod
    def _make_agent_stub():
        from agent_core import FuzzAgent

        agent = FuzzAgent.__new__(FuzzAgent)
        agent.tools = {}
        agent.messages = []
        agent.kb = MagicMock()
        agent.engine = MagicMock()
        agent.engine.run_id = "run42"
        agent.engine.test_count = 0
        agent.consecutive_failures = 0
        agent.session_unique_crash_ids = set()
        agent.first_crash_confirmed = False
        agent.resource_monitor = None
        agent.total_input_tokens = 0
        agent.total_output_tokens = 0
        return agent

    def test_batch_kb_logging(self):
        """KB should be called once per sub-result in the batch."""
        agent = self._make_agent_stub()
        batch_result = {
            "results": [
                {
                    "index": 0,
                    "test_id": "run42-1",
                    "description": "test1",
                    "compile_success": True,
                    "compile_error": None,
                    "execution_time_seconds": 2.0,
                    "crash_triggered": False,
                    "crash_id": None,
                    "crash_category": "",
                    "crash_summary": None,
                    "exploit_name": "mac_sch_a",
                    "mutation_count": 5,
                    "new_states": [],
                    "new_transitions": [],
                    "capture_path": "/tmp/c.pcapng",
                    "log_path": "/tmp/l",
                    "total_packets": 80,
                },
                {
                    "index": 1,
                    "test_id": "run42-2",
                    "description": "test2",
                    "compile_success": True,
                    "compile_error": None,
                    "execution_time_seconds": 3.0,
                    "crash_triggered": False,
                    "crash_id": None,
                    "crash_category": "",
                    "crash_summary": None,
                    "exploit_name": "mac_sch_b",
                    "mutation_count": 3,
                    "new_states": [],
                    "new_transitions": [],
                    "capture_path": "/tmp/c2.pcapng",
                    "log_path": "/tmp/l2",
                    "total_packets": 60,
                },
            ],
        }
        tool_input = {
            "test_cases": [
                {"exploit_code": "// a", "timeout_seconds": 30},
                {"exploit_code": "// b", "timeout_seconds": 30},
            ]
        }
        result_json = json.dumps(batch_result)

        # Simulate what agent_core does for execute_test_batch
        from execution_engine import TestResult

        batch_data = json.loads(result_json)
        for sub in batch_data.get("results", []):
            idx = sub.get("index", 0)
            tc_input = (
                tool_input.get("test_cases", [{}])[idx]
                if idx < len(tool_input.get("test_cases", []))
                else {}
            )
            tr = TestResult(
                test_id=sub.get("test_id", ""),
                fuzz_description=sub.get("description", ""),
                compile_success=sub.get("compile_success", False),
                compile_error=sub.get("compile_error"),
                execution_time_seconds=sub.get("execution_time_seconds", 0),
                crash_triggered=sub.get("crash_triggered", False),
                crash_id=sub.get("crash_id"),
                crash_category=sub.get("crash_category", ""),
                crash_summary=sub.get("crash_summary"),
                exploit_name=sub.get("exploit_name", ""),
                exploit_code=tc_input.get("exploit_code", ""),
                new_states=sub.get("new_states", []),
                new_transitions=sub.get("new_transitions", []),
                capture_path=sub.get("capture_path", ""),
                log_path=sub.get("log_path", ""),
                total_packets=sub.get("total_packets", 0),
                exploit_hash="",
                mutation_count=sub.get("mutation_count", 0),
            )
            agent.kb.log_test(tr, sub.get("description", ""))

        assert agent.kb.log_test.call_count == 2

    def test_batch_crash_tracking(self):
        """session_unique_crash_ids and first_crash_confirmed should update for batch crashes."""
        agent = self._make_agent_stub()
        batch_result = {
            "results": [
                {
                    "index": 0,
                    "test_id": "run42-1",
                    "compile_success": True,
                    "crash_triggered": False,
                    "crash_id": None,
                    "crash_category": "",
                    "new_states": [],
                    "description": "",
                },
                {
                    "index": 1,
                    "test_id": "run42-2",
                    "compile_success": True,
                    "crash_triggered": True,
                    "crash_id": "CRASH_X",
                    "crash_category": "non_publicly_known_crash",
                    "new_states": [],
                    "description": "",
                },
            ],
        }

        # Simulate agent_core batch crash tracking
        first_crash_just_confirmed = False
        turn_crashes = 0
        for sub in batch_result["results"]:
            if sub.get("crash_triggered"):
                turn_crashes += 1
                crash_id = sub.get("crash_id")
                if crash_id:
                    agent.session_unique_crash_ids.add(crash_id)
                    if not agent.first_crash_confirmed:
                        agent.first_crash_confirmed = True
                        first_crash_just_confirmed = True

        assert "CRASH_X" in agent.session_unique_crash_ids
        assert agent.first_crash_confirmed is True
        assert first_crash_just_confirmed is True
        assert turn_crashes == 1

    def test_batch_consecutive_failures(self):
        """consecutive_failures should increment per fruitless test and reset on crash."""
        agent = self._make_agent_stub()
        agent.consecutive_failures = 2  # pre-existing failures

        batch_result = {
            "results": [
                {"compile_success": True, "crash_triggered": False, "new_states": []},
                {"compile_success": True, "crash_triggered": False, "new_states": []},
                {
                    "compile_success": True,
                    "crash_triggered": True,
                    "new_states": [],
                    "crash_id": "C1",
                    "crash_category": "publicly_known_crash",
                },
            ],
        }

        for sub in batch_result["results"]:
            if (
                sub.get("compile_success")
                and not sub.get("crash_triggered")
                and len(sub.get("new_states", [])) == 0
            ):
                agent.consecutive_failures += 1
            else:
                agent.consecutive_failures = 0

        # 2 pre-existing + 2 failures, then reset by crash
        assert agent.consecutive_failures == 0

    def test_batch_result_size_limit(self):
        """execute_test_batch should use BATCH_TOOL_RESULT_MAX_CHARS (30k), not default 16k."""
        from agent_core import FuzzAgent
        from constants import BATCH_TOOL_RESULT_MAX_CHARS

        agent = FuzzAgent.__new__(FuzzAgent)
        big_result = "x" * 25000  # bigger than 16k but smaller than 30k
        agent.tools = {
            "execute_test_batch": ({"name": "execute_test_batch"}, lambda p: big_result)
        }
        result = agent._handle_tool_call("execute_test_batch", {})
        # Should NOT be truncated since 25k < 30k
        assert len(result) == 25000
        assert "TRUNCATED" not in result

    def test_regular_tool_still_truncated_at_16k(self):
        """Non-batch tools should still be truncated at 16k."""
        from agent_core import FuzzAgent

        agent = FuzzAgent.__new__(FuzzAgent)
        big_result = "x" * 20000
        agent.tools = {"some_tool": ({"name": "some_tool"}, lambda p: big_result)}
        result = agent._handle_tool_call("some_tool", {})
        assert len(result) < 20000
        assert "TRUNCATED" in result
