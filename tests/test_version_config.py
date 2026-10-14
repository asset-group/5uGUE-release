"""Tests for version_config.py — RQ1 experiment version configurations."""

import pytest

from version_config import FuzzerVersion, get_version_config


class TestVersionConfigFactory:
    def test_v1_config(self):
        cfg = get_version_config("v1")
        assert cfg.version == FuzzerVersion.V1
        assert not cfg.include_crash_patterns
        assert not cfg.include_strategy_hints
        assert not cfg.load_known_crashes
        assert not cfg.load_global_kb
        assert not cfg.load_session_history
        assert cfg.enable_local_papers
        assert cfg.enable_web_tools
        assert not cfg.enable_github_fetch
        assert not cfg.enable_batch_testing
        assert cfg.restrict_exploits_to_session
        assert cfg.blocked_domains == ()

    def test_v2_config(self):
        cfg = get_version_config("v2")
        assert cfg.version == FuzzerVersion.V2
        assert not cfg.include_crash_patterns
        assert not cfg.include_strategy_hints
        assert not cfg.load_known_crashes
        assert not cfg.load_global_kb
        assert not cfg.load_session_history
        assert cfg.enable_local_papers
        assert cfg.enable_web_tools
        assert cfg.enable_github_fetch
        assert not cfg.enable_batch_testing
        assert cfg.restrict_exploits_to_session
        assert cfg.blocked_domains == ()

    def test_v3_config(self):
        cfg = get_version_config("v3")
        assert cfg.version == FuzzerVersion.V3
        assert not cfg.include_crash_patterns
        assert not cfg.load_global_kb
        assert cfg.enable_local_papers
        assert cfg.enable_web_tools
        assert cfg.enable_github_fetch
        assert cfg.enable_batch_testing
        assert cfg.restrict_exploits_to_session
        assert cfg.blocked_domains == ()

    def test_v3f_config(self):
        cfg = get_version_config("v3f")
        assert cfg.version == FuzzerVersion.V3F
        assert not cfg.include_crash_patterns
        assert not cfg.load_global_kb
        assert not cfg.enable_local_papers
        assert cfg.enable_web_tools
        assert not cfg.enable_github_fetch
        assert cfg.enable_batch_testing
        assert cfg.restrict_exploits_to_session
        assert "github.com" in cfg.blocked_domains
        assert "asset-group.github.io" in cfg.blocked_domains

    def test_v3f_prompt_paper_instructions_replacement(self):
        from prompts.fiveg.templates import RESEARCH_TEMPLATE
        from prompts.system import build_research_prompt

        # Verify raw RESEARCH_TEMPLATE contains the exact paper tools sentence
        assert (
            "Use `query_papers` and `read_paper` for the local paper collection."
            in RESEARCH_TEMPLATE
        )

        # For V3 (enable_local_papers=True), paper instructions are present
        cfg_v3 = get_version_config("v3")
        prompt_v3 = build_research_prompt(cfg_v3, "MediaTek", "fiveg")
        assert "query_papers" in prompt_v3
        assert "read_paper" in prompt_v3

        # For V3F (enable_local_papers=False), paper instructions are dynamically replaced/filtered
        cfg_v3f = get_version_config("v3f")
        prompt_v3f = build_research_prompt(cfg_v3f, "MediaTek", "fiveg")
        assert "query_papers" not in prompt_v3f
        assert "read_paper" not in prompt_v3f
        assert "list_paper_categories" not in prompt_v3f
        assert "local paper collection" not in prompt_v3f

    def test_full_config(self):
        cfg = get_version_config("full")
        assert cfg.version == FuzzerVersion.FULL
        assert cfg.include_crash_patterns
        assert cfg.include_strategy_hints
        assert cfg.load_known_crashes
        assert cfg.load_global_kb
        assert cfg.load_session_history
        assert cfg.enable_local_papers
        assert cfg.enable_web_tools
        assert cfg.enable_github_fetch
        assert cfg.enable_batch_testing
        assert not cfg.restrict_exploits_to_session
        assert cfg.blocked_domains == ()

    def test_factory_rejects_invalid(self):
        with pytest.raises(ValueError, match="Invalid version"):
            get_version_config("v99")

    def test_config_is_frozen(self):
        cfg = get_version_config("v1")
        with pytest.raises(AttributeError):
            cfg.include_crash_patterns = True
