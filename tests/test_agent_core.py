"""Test agent core logic (FuzzAgent message handling, tool dispatch)."""

import json

import pytest

from constants import NORMAL_CAPTURE
from version_config import get_version_config
from device_profile import load_device_profile


@pytest.fixture(scope="module")
def mtk_profile():
    return load_device_profile("mediatek", "fiveg")


@pytest.fixture(scope="module")
def bt_profile():
    return load_device_profile("esp32", "bt")


class TestAgentToolDispatch:
    def test_handle_unknown_tool(self):
        from agent_core import FuzzAgent

        agent = FuzzAgent.__new__(FuzzAgent)
        agent.tools = {}
        result = agent._handle_tool_call("nonexistent_tool", {})
        parsed = json.loads(result)
        assert "error" in parsed
        assert "Unknown tool" in parsed["error"]

    def test_handle_tool_truncation(self):
        """Results exceeding TOOL_RESULT_MAX_CHARS should be truncated."""
        from agent_core import FuzzAgent

        agent = FuzzAgent.__new__(FuzzAgent)

        big_result = "x" * 20000
        agent.tools = {"test_tool": ({"name": "test_tool"}, lambda p: big_result)}
        result = agent._handle_tool_call("test_tool", {})
        assert (
            len(result) <= FuzzAgent.TOOL_RESULT_MAX_CHARS + 100
        )  # some slack for truncation message


class TestPrompts:
    def test_build_system_prompt_full(self, mtk_profile):
        from prompts.system import build_system_prompt

        config = get_version_config("full")
        prompt = build_system_prompt(config=config, profile=mtk_profile)
        assert "5G NR" in prompt
        assert "WDissector" in prompt
        assert "Known MediaTek Crash Patterns" in prompt
        assert "adjacent bytes" in prompt  # strategy hints

    def test_build_system_prompt_v1_no_crash_patterns(self, mtk_profile):
        from prompts.system import build_system_prompt

        config = get_version_config("v1")
        prompt = build_system_prompt(config=config, profile=mtk_profile)
        assert "5G NR" in prompt
        assert "WDissector" in prompt
        assert "Known MediaTek Crash Patterns" not in prompt
        assert "0x5b" not in prompt
        assert "spCellConfig" not in prompt
        assert "adjacent bytes" not in prompt

    def test_build_system_prompt_backward_compat(self, mtk_profile):
        """build_system_prompt() with profile defaults to FULL."""
        from prompts.system import build_system_prompt

        prompt = build_system_prompt(profile=mtk_profile)
        assert "Known MediaTek Crash Patterns" in prompt

    def test_build_system_prompt_with_strategy(self):
        from prompts.system import build_system_prompt

        prompt = build_system_prompt("Focus on RRC SecurityModeCommand")
        assert "RRC SecurityModeCommand" in prompt

    def test_build_initial_briefing(self):
        from prompts.system import build_initial_briefing

        briefing = build_initial_briefing(
            '[{"filter": "nr-rrc.c1 == 1"}]', capture_path="/test/capture.pcapng"
        )
        assert "/test/capture.pcapng" in briefing
        assert "packet_types" in briefing
        assert "nr-rrc.c1" in briefing

    def test_initial_briefing_includes_capture_path(self):
        from prompts.system import build_initial_briefing

        briefing = build_initial_briefing("[]", capture_path=NORMAL_CAPTURE)
        assert NORMAL_CAPTURE in briefing
        assert "IMPORTANT" in briefing

    def test_v1_workflow_has_research_no_github(self):
        from prompts.system import build_system_prompt

        config = get_version_config("v1")
        prompt = build_system_prompt(config=config)
        assert "query_papers" in prompt
        assert "web_search" in prompt
        assert "GitHub Repository Navigation" not in prompt
        assert "execute_test_batch" not in prompt

    def test_v2_workflow_mentions_local_papers_only(self):
        from prompts.system import build_system_prompt

        config = get_version_config("v2")
        prompt = build_system_prompt(config=config)
        assert "query_papers" in prompt
        assert "read_paper" in prompt
        assert "list_paper_categories" in prompt

    def test_v3_workflow_mentions_web_and_papers(self):
        from prompts.system import build_system_prompt

        config = get_version_config("v3")
        prompt = build_system_prompt(config=config)
        assert "web_search" in prompt
        assert "fetch_url" in prompt
        assert "query_papers" in prompt

    def test_build_system_prompt_bluetooth(self, bt_profile):
        from prompts.system import build_system_prompt

        config = get_version_config("full")
        prompt = build_system_prompt(config=config, profile=bt_profile)
        assert "Bluetooth host" in prompt
        assert "peripheral" in prompt
        assert "bt_fuzzer" in prompt
        assert "btbrlmp.op == 40" in prompt
        assert "L2CAP" in prompt
        assert "SDP" in prompt
        assert "LMP" in prompt
        assert "ADB device tools" not in prompt
        assert "adb_logcat" not in prompt

    def test_build_initial_briefing_bluetooth(self, bt_profile):
        from prompts.system import build_initial_briefing

        briefing = build_initial_briefing(
            '[{"filter": "btl2cap.cmd_code == 1"}]',
            capture_path="/test/capture.pcapng",
            profile=bt_profile,
        )
        assert "/test/capture.pcapng" in briefing
        assert "Bluetooth host" in briefing
        assert "peripheral" in briefing
        assert "L2CAP, SDP, LMP" in briefing
        assert "5G NR" not in briefing

    def test_build_cold_start_prompt_bluetooth(self):
        from prompts.system import build_cold_start_prompt

        prompt = build_cold_start_prompt(
            target_vendor="Espressif",
            protocol="bt",
        )
        assert "Espressif" in prompt
        assert "L2CAP vulnerability" in prompt
        assert "SDP vulnerability" in prompt
        assert "LMP vulnerability" in prompt
        assert "RRC" not in prompt


class TestToolRegistry:
    def _make_kb(self):
        from knowledge_base import KnowledgeBase
        import tempfile
        import os

        tmpdir = tempfile.mkdtemp()
        kb = KnowledgeBase.__new__(KnowledgeBase)
        kb.session_id = "test"
        kb.enable_global_kb = True
        kb.dir = tmpdir
        kb.tests_path = os.path.join(tmpdir, "tests.jsonl")
        kb.findings_path = os.path.join(tmpdir, "findings.jsonl")
        kb.strategy_path = os.path.join(tmpdir, "strategy.md")
        kb._test_hashes = set()
        kb._finding_count = 0
        kb._test_count = 0
        return kb, tmpdir

    def test_full_all_tools_registered(self, wd_tool, td_utils):
        import shutil

        kb, tmpdir = self._make_kb()
        try:
            from tools import build_tool_registry

            config = get_version_config("full")
            tools = build_tool_registry(
                wd_tool, td_utils, engine=None, kb=kb, config=config
            )

            expected_tools = [
                "list_packet_types",
                "inspect_packets",
                "get_packet_hex",
                "get_field_info",
                "search_fields",
                "view_state_machine",
                "analyze_crash_log",
                "compare_crashes",
                "read_device_log",
                "submit_custom_exploit",
                "execute_test",
                "read_exploit_source",
                "list_exploits",
                "save_finding",
                "query_findings",
                "get_test_history",
                "update_strategy",
                "promote_finding",
                "query_global_findings",
                "fetch_url",
                "web_search",
                "query_papers",
                "read_paper",
                "list_paper_categories",
            ]
            for name in expected_tools:
                assert name in tools, f"Tool '{name}' not registered in FULL config"

            for name, (schema, handler) in tools.items():
                assert "name" in schema
                assert "input_schema" in schema
                assert callable(handler)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_v1_research_tools_no_batch(self, wd_tool, td_utils):
        import shutil

        kb, tmpdir = self._make_kb()
        kb.enable_global_kb = False
        try:
            from tools import build_tool_registry

            config = get_version_config("v1")
            tools = build_tool_registry(
                wd_tool, td_utils, engine=None, kb=kb, config=config
            )

            # Core tools present
            core = [
                "list_packet_types",
                "inspect_packets",
                "get_field_info",
                "submit_custom_exploit",
                "execute_test",
                "read_exploit_source",
                "list_exploits",
                "save_finding",
                "query_findings",
                "get_test_history",
                "update_strategy",
            ]
            for name in core:
                assert name in tools, f"Core tool '{name}' missing in V1"

            # V1 has web + paper tools
            assert "fetch_url" in tools, "V1 should have fetch_url"
            assert "web_search" in tools, "V1 should have web_search"
            assert "query_papers" in tools, "V1 should have query_papers"
            assert "read_paper" in tools, "V1 should have read_paper"

            # No batch testing or global tools
            absent = [
                "execute_test_batch",
                "promote_finding",
                "query_global_findings",
            ]
            for name in absent:
                assert name not in tools, f"Tool '{name}' should NOT be in V1"
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_v2_full_research_no_batch(self, wd_tool, td_utils):
        import shutil

        kb, tmpdir = self._make_kb()
        kb.enable_global_kb = False
        try:
            from tools import build_tool_registry

            config = get_version_config("v2")
            tools = build_tool_registry(
                wd_tool, td_utils, engine=None, kb=kb, config=config
            )

            # V2 has paper + web tools
            assert "query_papers" in tools
            assert "read_paper" in tools
            assert "list_paper_categories" in tools
            assert "fetch_url" in tools, "V2 should have fetch_url"
            assert "web_search" in tools, "V2 should have web_search"

            # No batch testing or global tools
            absent = [
                "execute_test_batch",
                "promote_finding",
                "query_global_findings",
            ]
            for name in absent:
                assert name not in tools, f"Tool '{name}' should NOT be in V2"
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_v3_full_research(self, wd_tool, td_utils):
        import shutil

        kb, tmpdir = self._make_kb()
        kb.enable_global_kb = False
        try:
            from tools import build_tool_registry

            config = get_version_config("v3")
            tools = build_tool_registry(
                wd_tool, td_utils, engine=None, kb=kb, config=config
            )

            # All research tools present
            research = [
                "fetch_url",
                "web_search",
                "query_papers",
                "read_paper",
                "list_paper_categories",
            ]
            for name in research:
                assert name in tools, f"Research tool '{name}' missing in V3"

            # No global KB tools
            assert "promote_finding" not in tools
            assert "query_global_findings" not in tools
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
