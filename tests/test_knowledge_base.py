"""Test KnowledgeBase persistence and queries."""

import os
import shutil
import tempfile

import pytest


@pytest.fixture
def tmp_kb():
    """Create a KnowledgeBase with a temp directory."""
    tmpdir = tempfile.mkdtemp()
    from knowledge_base import KnowledgeBase

    kb = KnowledgeBase.__new__(KnowledgeBase)
    kb.session_id = "test_session"
    kb.dir = os.path.join(tmpdir, "test_session")
    os.makedirs(kb.dir, exist_ok=True)
    kb.tests_path = os.path.join(kb.dir, "tests.jsonl")
    kb.findings_path = os.path.join(kb.dir, "findings.jsonl")
    kb.strategy_path = os.path.join(kb.dir, "strategy.md")
    kb._test_hashes = set()
    kb._finding_count = 0
    kb._test_count = 0
    kb.global_findings_path = os.path.join(tmpdir, "global", "findings.jsonl")
    kb._global_dedup_keys = set()
    yield kb
    shutil.rmtree(tmpdir, ignore_errors=True)


class TestKnowledgeBase:
    def test_init_creates_dirs(self, tmp_kb):
        assert os.path.isdir(tmp_kb.dir)

    def test_empty_state(self, tmp_kb):
        assert tmp_kb.test_count == 0
        assert tmp_kb.get_test_history() == []
        assert tmp_kb.query_findings() == []
        assert tmp_kb.get_strategy() == ""

    def test_update_and_get_strategy(self, tmp_kb):
        tmp_kb.update_strategy("# My Strategy\nFocus on RRC")
        assert "My Strategy" in tmp_kb.get_strategy()
        assert "RRC" in tmp_kb.get_strategy()

    def test_save_and_query_findings(self, tmp_kb):
        tmp_kb.save_finding("RRC SMC crash", tags=["crash", "rrc"], related_tests=[1])
        tmp_kb.save_finding("NAS auth anomaly", tags=["anomaly", "nas"])

        all_findings = tmp_kb.query_findings()
        assert len(all_findings) == 2

        crash_findings = tmp_kb.query_findings(tag="crash")
        assert len(crash_findings) == 1
        assert "RRC SMC" in crash_findings[0]["description"]

        nas_findings = tmp_kb.query_findings(field="auth")
        assert len(nas_findings) == 1

    def test_has_been_tested(self, tmp_kb):
        assert not tmp_kb.has_been_tested("abc123")
        tmp_kb._test_hashes.add("abc123")
        assert tmp_kb.has_been_tested("abc123")

    def test_persistence(self, tmp_kb):
        """Data persists when KnowledgeBase is re-created."""
        tmp_kb.save_finding("test finding", tags=["test"])
        tmp_kb.update_strategy("persisted strategy")

        # Re-create KB from same directory
        from knowledge_base import KnowledgeBase

        kb2 = KnowledgeBase.__new__(KnowledgeBase)
        kb2.session_id = tmp_kb.session_id
        kb2.dir = tmp_kb.dir
        kb2.tests_path = tmp_kb.tests_path
        kb2.findings_path = tmp_kb.findings_path
        kb2.strategy_path = tmp_kb.strategy_path
        kb2._test_hashes = set()
        kb2._finding_count = 0
        kb2._test_count = 0
        kb2._load_existing()

        assert kb2.get_strategy() == "persisted strategy"
        assert len(kb2.query_findings()) == 1
