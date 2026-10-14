"""Tests for memory_tools: save_finding, query_findings, get_test_history, update_strategy wrappers."""

import json
import os
import tempfile
import shutil
from unittest.mock import patch

import pytest


def _make_kb(tmpdir, session_id="mem_test"):
    from knowledge_base import KnowledgeBase

    global_dir = os.path.join(tmpdir, "global")
    with (
        patch("knowledge_base.KB_PATH", tmpdir),
        patch("knowledge_base.GLOBAL_KB_PATH", global_dir),
    ):
        return KnowledgeBase(session_id)


def _make_test_result(**overrides):
    from execution_engine import TestResult

    defaults = dict(
        test_id="run-1",
        fuzz_description="test",
        compile_success=True,
        compile_error=None,
        execution_time_seconds=1.0,
        crash_triggered=False,
        crash_id=None,
        crash_category="",
        crash_summary=None,
        exploit_name="mac_sch_t",
        exploit_code="code",
        new_states=[],
        new_transitions=[],
        capture_path="",
        log_path="",
        total_packets=10,
        exploit_hash="h1",
        mutation_count=1,
        mutation_log_lines=[],
    )
    defaults.update(overrides)
    return TestResult(**defaults)


@pytest.fixture
def mem_tools():
    tmpdir = tempfile.mkdtemp()
    kb = _make_kb(tmpdir)
    from tools.memory_tools import get_memory_tools

    tools = get_memory_tools(kb)
    yield tools, kb, tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


class TestSaveFindingTool:
    def test_saves_and_returns_entry(self, mem_tools):
        tools, kb, _ = mem_tools
        _, handler = tools["save_finding"]
        result = json.loads(
            handler(
                {
                    "description": "RRC crash at offset 63",
                    "tags": ["crash", "rrc"],
                    "related_tests": [1, 2],
                }
            )
        )
        assert result["finding_id"] == 1
        assert result["description"] == "RRC crash at offset 63"
        assert "crash" in result["tags"]
        assert result["related_tests"] == [1, 2]
        assert "timestamp" in result

    def test_default_tags_and_related(self, mem_tools):
        tools, _, _ = mem_tools
        _, handler = tools["save_finding"]
        result = json.loads(handler({"description": "observation"}))
        assert result["tags"] == []
        assert result["related_tests"] == []

    def test_increments_finding_id(self, mem_tools):
        tools, _, _ = mem_tools
        _, handler = tools["save_finding"]
        r1 = json.loads(handler({"description": "first"}))
        r2 = json.loads(handler({"description": "second"}))
        assert r1["finding_id"] == 1
        assert r2["finding_id"] == 2


class TestQueryFindingsTool:
    def test_query_all(self, mem_tools):
        tools, kb, _ = mem_tools
        kb.save_finding("f1", tags=["a"])
        kb.save_finding("f2", tags=["b"])

        _, handler = tools["query_findings"]
        result = json.loads(handler({}))
        assert len(result) == 2

    def test_query_by_tag(self, mem_tools):
        tools, kb, _ = mem_tools
        kb.save_finding("crash finding", tags=["crash"])
        kb.save_finding("normal finding", tags=["info"])

        _, handler = tools["query_findings"]
        result = json.loads(handler({"tag": "crash"}))
        assert len(result) == 1
        assert "crash finding" in result[0]["description"]

    def test_query_by_field(self, mem_tools):
        tools, kb, _ = mem_tools
        kb.save_finding("RRC setup issue", tags=["rrc"])
        kb.save_finding("NAS problem", tags=["nas"])

        _, handler = tools["query_findings"]
        result = json.loads(handler({"field": "NAS"}))
        assert len(result) == 1

    def test_query_no_results(self, mem_tools):
        tools, _, _ = mem_tools
        _, handler = tools["query_findings"]
        result = json.loads(handler({"tag": "nonexistent"}))
        assert result == []


class TestGetTestHistoryTool:
    def test_empty_history(self, mem_tools):
        tools, _, _ = mem_tools
        _, handler = tools["get_test_history"]
        result = json.loads(handler({}))
        assert result == []

    def test_returns_logged_tests(self, mem_tools):
        tools, kb, _ = mem_tools
        kb.log_test(_make_test_result(test_id="t1"), "desc1")
        kb.log_test(_make_test_result(test_id="t2", exploit_hash="h2"), "desc2")

        _, handler = tools["get_test_history"]
        result = json.loads(handler({}))
        assert len(result) == 2
        assert result[0]["test_id"] == "t1"

    def test_respects_limit(self, mem_tools):
        tools, kb, _ = mem_tools
        for i in range(10):
            kb.log_test(
                _make_test_result(test_id=f"t{i}", exploit_hash=f"h{i}"), f"d{i}"
            )

        _, handler = tools["get_test_history"]
        result = json.loads(handler({"limit": 3}))
        assert len(result) == 3

    def test_default_limit(self, mem_tools):
        tools, kb, _ = mem_tools
        for i in range(5):
            kb.log_test(
                _make_test_result(test_id=f"t{i}", exploit_hash=f"h{i}"), f"d{i}"
            )

        _, handler = tools["get_test_history"]
        result = json.loads(handler({}))
        assert len(result) == 5


class TestUpdateStrategyTool:
    def test_updates_strategy(self, mem_tools):
        tools, kb, _ = mem_tools
        _, handler = tools["update_strategy"]
        result = json.loads(handler({"content": "Focus on RRC truncation"}))
        assert result["status"] == "Strategy updated"
        assert result["length"] == len("Focus on RRC truncation")
        assert kb.get_strategy() == "Focus on RRC truncation"

    def test_overwrites_previous(self, mem_tools):
        tools, kb, _ = mem_tools
        _, handler = tools["update_strategy"]
        handler({"content": "Plan A"})
        handler({"content": "Plan B"})
        assert kb.get_strategy() == "Plan B"

    def test_returns_length(self, mem_tools):
        tools, _, _ = mem_tools
        _, handler = tools["update_strategy"]
        result = json.loads(handler({"content": "short"}))
        assert result["length"] == 5
