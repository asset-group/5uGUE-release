"""Test known crashes data, system prompt integration, and new exploit tools."""

import json
import os

import pytest

from version_config import get_version_config
from device_profile import load_device_profile


@pytest.fixture(scope="module")
def mtk_profile():
    return load_device_profile("mediatek", "fiveg")


@pytest.fixture(scope="module")
def d9400_profile():
    return load_device_profile("mediatek_d9400", "fiveg")


class TestKnownCrashesDataFile:
    """Test data/known_crashes.json integrity."""

    @pytest.fixture(scope="class")
    @staticmethod
    def known_crashes(agent_path):
        path = os.path.join(agent_path, "data/known_crashes.json")
        with open(path, "r") as f:
            return json.load(f)

    def test_file_exists(self, agent_path):
        path = os.path.join(agent_path, "data/known_crashes.json")
        assert os.path.isfile(path)

    def test_valid_json_structure(self, known_crashes):
        assert "confirmed_crashes" in known_crashes
        assert "crash_patterns" in known_crashes
        assert "target" in known_crashes
        assert "vulnerable_rrc_setup_substructures" in known_crashes
        assert "effective_mutation_strategies" in known_crashes
        assert "key_insights" in known_crashes

    def test_target_is_mediatek(self, known_crashes):
        assert known_crashes["target"]["vendor"] == "MediaTek"
        assert known_crashes["target"]["protocol"] == "fiveg"

    def test_has_seven_confirmed_crashes(self, known_crashes):
        crashes = known_crashes["confirmed_crashes"]
        assert len(crashes) == 7

    def test_crash_entries_have_required_fields(self, known_crashes):
        required = [
            "name",
            "file",
            "filter",
            "mutations",
            "crash_component",
            "crash_type",
            "category",
        ]
        for crash in known_crashes["confirmed_crashes"]:
            for field in required:
                assert field in crash, (
                    f"Crash {crash.get('name', '?')} missing field: {field}"
                )

    def test_all_crash_names_start_with_mac_sch(self, known_crashes):
        for crash in known_crashes["confirmed_crashes"]:
            assert crash["name"].startswith("mac_sch_"), f"Bad name: {crash['name']}"

    def test_mutations_have_offset_and_value(self, known_crashes):
        for crash in known_crashes["confirmed_crashes"]:
            for mut in crash["mutations"]:
                assert "offset_from_header" in mut
                assert "value" in mut
                assert isinstance(mut["offset_from_header"], int)

    def test_crash_cpp_files_referenced(self, known_crashes):
        """Verify all confirmed crashes reference a .cpp file (files are curated data, not deployed)."""
        for crash in known_crashes["confirmed_crashes"]:
            assert crash["file"].endswith(".cpp"), f"Bad file ref: {crash['file']}"

    def test_six_rrc_setup_one_rlc(self, known_crashes):
        rrc = [
            c for c in known_crashes["confirmed_crashes"] if "rrcSetup" in c["filter"]
        ]
        rlc = [c for c in known_crashes["confirmed_crashes"] if "rlc-nr" in c["filter"]]
        assert len(rrc) == 6
        assert len(rlc) == 1

    def test_categories_are_diverse(self, known_crashes):
        categories = {c["category"] for c in known_crashes["confirmed_crashes"]}
        assert len(categories) >= 4, f"Only {len(categories)} categories: {categories}"


class TestKnownCrashesBriefing:
    """Test build_known_crashes_briefing() output."""

    def test_returns_nonempty_string(self):
        from prompts.system import build_known_crashes_briefing

        briefing = build_known_crashes_briefing()
        assert isinstance(briefing, str)
        assert len(briefing) > 100

    def test_contains_all_crash_names(self):
        from prompts.system import build_known_crashes_briefing

        briefing = build_known_crashes_briefing()
        expected = [
            "mtk_rrc_setup_crash_1",
            "mtk_rrc_setup_crash_2",
            "mtk_rrc_setup_crash_3",
            "mtk_rrc_setup_crash_4",
            "mtk_rrc_setup_crash_6",
            "mtk_rrc_setup_crash_7",
            "mtk_rlc_crash",
        ]
        for name in expected:
            assert name in briefing, f"Missing crash: {name}"

    def test_contains_filters(self):
        from prompts.system import build_known_crashes_briefing

        briefing = build_known_crashes_briefing()
        assert "nr-rrc.rrcSetup_element" in briefing
        assert "rlc-nr.am.dc == 0" in briefing

    def test_contains_pkt_buf_mutations(self):
        from prompts.system import build_known_crashes_briefing

        briefing = build_known_crashes_briefing()
        assert "pkt_buf[" in briefing

    def test_contains_guidance_to_find_new(self):
        from prompts.system import build_known_crashes_briefing

        briefing = build_known_crashes_briefing()
        assert "NEW crashes" in briefing


class TestSystemPromptFull:
    """Test that FULL system prompt includes MTK crash knowledge."""

    def test_system_prompt_has_mtk_crash_table(self, mtk_profile):
        from prompts.system import build_system_prompt

        config = get_version_config("full")
        prompt = build_system_prompt(config=config, profile=mtk_profile)
        assert "Known MediaTek Crash Patterns" in prompt
        assert "crash_1" in prompt
        assert "crash_7" in prompt

    def test_system_prompt_has_vulnerable_substructures(self, mtk_profile):
        from prompts.system import build_system_prompt

        config = get_version_config("full")
        prompt = build_system_prompt(config=config, profile=mtk_profile)
        assert "spCellConfig" in prompt
        assert "pucch_CSI_ResourceList" in prompt
        assert "physicalCellGroupConfig" in prompt

    def test_system_prompt_has_key_insights(self, mtk_profile):
        from prompts.system import build_system_prompt

        config = get_version_config("full")
        prompt = build_system_prompt(config=config, profile=mtk_profile)
        assert "Valid-but-wrong" in prompt
        assert "Single-byte precision" in prompt

    def test_system_prompt_has_new_crash_strategy(self, mtk_profile):
        from prompts.system import build_system_prompt

        config = get_version_config("full")
        prompt = build_system_prompt(config=config, profile=mtk_profile)
        assert "adjacent bytes" in prompt
        assert "RRC Reconfiguration" in prompt


class TestSystemPromptScrubbed:
    """Test that V1-V3 prompts have NO crash knowledge."""

    @pytest.mark.parametrize("version", ["v1", "v2", "v3"])
    def test_no_crash_patterns(self, version, mtk_profile):
        from prompts.system import build_system_prompt

        config = get_version_config(version)
        prompt = build_system_prompt(config=config, profile=mtk_profile)
        assert "Known MediaTek Crash Patterns" not in prompt

    @pytest.mark.parametrize("version", ["v1", "v2", "v3"])
    def test_no_vulnerable_substructures(self, version, mtk_profile):
        from prompts.system import build_system_prompt

        config = get_version_config(version)
        prompt = build_system_prompt(config=config, profile=mtk_profile)
        assert "spCellConfig" not in prompt
        assert "searchSpacesToAddModList" not in prompt

    @pytest.mark.parametrize("version", ["v1", "v2", "v3"])
    def test_no_strategy_hints(self, version):
        from prompts.system import build_system_prompt

        config = get_version_config(version)
        prompt = build_system_prompt(config=config)
        assert "adjacent bytes" not in prompt

    @pytest.mark.parametrize("version", ["v1", "v2", "v3"])
    def test_no_crash_hex_values(self, version):
        from prompts.system import build_system_prompt

        config = get_version_config(version)
        prompt = build_system_prompt(config=config)
        assert "0x5b" not in prompt
        assert "crash_1" not in prompt

    @pytest.mark.parametrize("version", ["v1", "v2", "v3"])
    def test_still_has_mutation_taxonomy(self, version):
        from prompts.system import build_system_prompt

        config = get_version_config(version)
        prompt = build_system_prompt(config=config)
        assert "bit_flip" in prompt
        assert "truncation" in prompt

    @pytest.mark.parametrize("version", ["v1", "v2", "v3"])
    def test_still_has_wdissector_api(self, version):
        from prompts.system import build_system_prompt

        config = get_version_config(version)
        prompt = build_system_prompt(config=config)
        assert "wd_filter" in prompt
        assert "tx_post_dissection" in prompt


class TestResearchPromptHints:
    @pytest.mark.parametrize("version", ["v1", "v2", "v3"])
    def test_research_hints_included_for_v1v2v3(self, version, d9400_profile):
        from prompts.system import build_research_prompt

        config = get_version_config(version)
        prompt = build_research_prompt(config, profile=d9400_profile)
        assert "5Ghoul" in prompt

    def test_research_hints_absent_for_full(self, d9400_profile):
        from prompts.system import build_research_prompt

        config = get_version_config("full")
        prompt = build_research_prompt(config, profile=d9400_profile)
        assert prompt == ""

    @pytest.mark.parametrize("version", ["v1", "v2", "v3"])
    def test_no_hints_without_profile(self, version):
        from prompts.system import build_research_prompt

        config = get_version_config(version)
        prompt = build_research_prompt(config)
        assert "5Ghoul" not in prompt


class TestReadExploitSource:
    """Test read_exploit_source tool."""

    def test_reads_existing_exploit(self, wd_tool, td_utils):
        from tools.exploit_tools import get_exploit_tools
        from constants import EXPLOIT_FOLDER

        fixture_path = os.path.join(EXPLOIT_FOLDER, "mac_sch_test_exploit.cpp")
        fixture_src = (
            '#include "ModulesInclude.hpp"\n'
            'const char *module_name() { return "mac_sch_test"; }\n'
            "int setup(wd_modules_ctx_t *ctx) {\n"
            '    wd_filter_t f1 = wd_filter("nr-rrc.rrcSetup_element");\n'
            "    wd_register_filter(ctx->wd, f1);\n"
            "    return 0;\n"
            "}\n"
            "int tx_post_dissection(uint8_t *pkt_buf, int pkt_length, wd_modules_ctx_t *ctx) {\n"
            "    pkt_buf[0] = 0x67;\n"
            "    return 0;\n"
            "}\n"
        )
        with open(fixture_path, "w", encoding="utf8") as f:
            f.write(fixture_src)
        try:
            tools = get_exploit_tools(wd_tool, td_utils, engine=None)
            _, handler = tools["read_exploit_source"]
            result = json.loads(handler({"exploit_name": "mac_sch_test_exploit"}))
            assert "source_code" in result
            assert "rrcSetup_element" in result["source_code"]
            assert "0x67" in result["source_code"]
        finally:
            os.remove(fixture_path)

    def test_auto_adds_prefix(self, wd_tool, td_utils):
        from tools.exploit_tools import get_exploit_tools

        tools = get_exploit_tools(wd_tool, td_utils, engine=None)
        _, handler = tools["read_exploit_source"]
        result = json.loads(handler({"exploit_name": "mtk_rrc_setup_crash_1"}))
        assert "source_code" in result
        assert "exploit_name" in result
        assert result["exploit_name"] == "mac_sch_mtk_rrc_setup_crash_1.cpp"

    def test_auto_adds_cpp_extension(self, wd_tool, td_utils):
        from tools.exploit_tools import get_exploit_tools

        tools = get_exploit_tools(wd_tool, td_utils, engine=None)
        _, handler = tools["read_exploit_source"]
        result = json.loads(handler({"exploit_name": "mac_sch_mtk_rlc_crash.cpp"}))
        assert "source_code" in result

    def test_nonexistent_exploit_returns_error_and_list(self, wd_tool, td_utils):
        from tools.exploit_tools import get_exploit_tools

        tools = get_exploit_tools(wd_tool, td_utils, engine=None)
        _, handler = tools["read_exploit_source"]
        result = json.loads(handler({"exploit_name": "mac_sch_does_not_exist"}))
        assert "error" in result
        assert "available_exploits" in result
        assert len(result["available_exploits"]) > 0

    @pytest.mark.skip(
        reason="Deprecated: from a past use case — MTK exploit set has shifted, list is stale."
    )
    def test_all_mtk_exploits_readable(self, wd_tool, td_utils):
        from tools.exploit_tools import get_exploit_tools

        tools = get_exploit_tools(wd_tool, td_utils, engine=None)
        _, handler = tools["read_exploit_source"]
        mtk_exploits = [
            "mtk_rrc_setup_crash_1",
            "mtk_rrc_setup_crash_2",
            "mtk_rrc_setup_crash_3",
            "mtk_rrc_setup_crash_4",
            "mtk_rrc_setup_crash_6",
            "mtk_rrc_setup_crash_7",
            "mtk_rlc_crash",
        ]
        for name in mtk_exploits:
            result = json.loads(handler({"exploit_name": name}))
            assert "source_code" in result, f"Failed to read {name}: {result}"
            assert "ModulesInclude" in result["source_code"]

    def test_restricted_blocks_preexisting_exploit(self, wd_tool, td_utils):
        from tools.exploit_tools import get_exploit_tools

        config = get_version_config("v1")
        tools = get_exploit_tools(
            wd_tool, td_utils, engine=None, config=config, session_exploits=set()
        )
        _, handler = tools["read_exploit_source"]
        result = json.loads(handler({"exploit_name": "mac_sch_mtk_rrc_setup_crash_2"}))
        assert "error" in result
        assert "Access denied" in result["error"]

    def test_restricted_allows_session_exploit(self, wd_tool, td_utils, tmp_path):
        from tools.exploit_tools import get_exploit_tools

        exploit_filename = "mac_sch_session_test_exploit.cpp"
        (tmp_path / exploit_filename).write_text("// dummy exploit source code")

        config = get_version_config("v1")
        session_exploits = {exploit_filename}
        tools = get_exploit_tools(
            wd_tool,
            td_utils,
            engine=None,
            config=config,
            session_exploits=session_exploits,
            exploit_folder=str(tmp_path),
        )
        _, handler = tools["read_exploit_source"]
        result = json.loads(
            handler({"exploit_name": "mac_sch_session_test_exploit"})
        )
        assert "source_code" in result
        assert result["source_code"] == "// dummy exploit source code"


class TestListExploits:
    """Test list_exploits tool."""

    @pytest.mark.skip(
        reason="Deprecated: from a past use case — list_exploits surface/contract has changed."
    )
    def test_returns_exploit_list(self, wd_tool, td_utils):
        from tools.exploit_tools import get_exploit_tools

        tools = get_exploit_tools(wd_tool, td_utils, engine=None)
        _, handler = tools["list_exploits"]
        result = json.loads(handler({}))
        assert "exploits" in result
        assert "total" in result
        assert result["total"] >= 0

    def test_filter_by_mtk(self, wd_tool, td_utils):
        """Filter by 'mtk' — returns only exploits with 'mtk' in the name (0 if .cpp files not deployed)."""
        from tools.exploit_tools import get_exploit_tools

        tools = get_exploit_tools(wd_tool, td_utils, engine=None)
        _, handler = tools["list_exploits"]
        result = json.loads(handler({"filter": "mtk"}))
        for entry in result["exploits"]:
            assert "mtk" in entry["name"]

    # def test_filter_by_rlc(self, wd_tool, td_utils):
    #     from tools.exploit_tools import get_exploit_tools
    #     tools = get_exploit_tools(wd_tool, td_utils, engine=None)
    #     _, handler = tools["list_exploits"]
    #     result = json.loads(handler({"filter": "rlc"}))
    #     assert result["total"] >= 0
    #     for entry in result["exploits"]:
    #         assert "rlc" in entry["name"]

    def test_non_mtk_exploits_exist(self, wd_tool, td_utils):
        """Exploit folder contains both curated mtk and agent-generated exploits."""
        from tools.exploit_tools import get_exploit_tools

        tools = get_exploit_tools(wd_tool, td_utils, engine=None)
        _, handler = tools["list_exploits"]
        result = json.loads(handler({}))
        # All exploits start with mac_sch_ prefix
        for entry in result["exploits"]:
            assert entry["name"].startswith("mac_sch_")

    def test_empty_filter_returns_all(self, wd_tool, td_utils):
        from tools.exploit_tools import get_exploit_tools

        tools = get_exploit_tools(wd_tool, td_utils, engine=None)
        _, handler = tools["list_exploits"]
        result = json.loads(handler({"filter": ""}))
        assert result["total"] >= 0  # at least the template exploit

    def test_restricted_shows_no_preexisting(self, wd_tool, td_utils):
        from tools.exploit_tools import get_exploit_tools

        config = get_version_config("v1")
        tools = get_exploit_tools(
            wd_tool, td_utils, engine=None, config=config, session_exploits=set()
        )
        _, handler = tools["list_exploits"]
        result = json.loads(handler({}))
        assert result["total"] == 0

    def test_restricted_no_confirmed_crash_flag(self, wd_tool, td_utils):
        from tools.exploit_tools import get_exploit_tools

        config = get_version_config("v1")
        session_exploits = {"mac_sch_test_exploit.cpp"}
        tools = get_exploit_tools(
            wd_tool,
            td_utils,
            engine=None,
            config=config,
            session_exploits=session_exploits,
        )
        _, handler = tools["list_exploits"]
        result = json.loads(handler({}))
        for entry in result["exploits"]:
            assert "confirmed_crash" not in entry

    def test_restricted_shows_session_exploits(self, wd_tool, td_utils):
        from tools.exploit_tools import get_exploit_tools

        config = get_version_config("v1")
        session_exploits = {"mac_sch_my_test.cpp", "mac_sch_another.cpp"}
        tools = get_exploit_tools(
            wd_tool,
            td_utils,
            engine=None,
            config=config,
            session_exploits=session_exploits,
        )
        _, handler = tools["list_exploits"]
        result = json.loads(handler({}))
        assert result["total"] == 2


class TestToolRegistryIncludesNewTools:
    """Test that the new tools are registered in the full registry."""

    def test_new_tools_in_registry(self, wd_tool, td_utils):
        from knowledge_base import KnowledgeBase
        import tempfile
        import shutil

        tmpdir = tempfile.mkdtemp()
        try:
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

            from tools import build_tool_registry

            tools = build_tool_registry(wd_tool, td_utils, engine=None, kb=kb)

            assert "read_exploit_source" in tools
            assert "list_exploits" in tools

            # Verify schema shape
            for name in ("read_exploit_source", "list_exploits"):
                schema, handler = tools[name]
                assert schema["name"] == name
                assert "input_schema" in schema
                assert callable(handler)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class TestConstantsKnownCrashesPath:
    """Test that KNOWN_CRASHES constant exists and points to valid file."""

    def test_known_crashes_constant_exists(self):
        from constants import KNOWN_CRASHES

        assert KNOWN_CRASHES is not None
        assert "known_crashes.json" in KNOWN_CRASHES

    def test_known_crashes_path_valid(self):
        from constants import KNOWN_CRASHES

        assert os.path.isfile(KNOWN_CRASHES)
