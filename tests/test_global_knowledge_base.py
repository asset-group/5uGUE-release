"""Tests for global knowledge base: promotion, dedup, cross-session loading."""

import json
import os
import shutil
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


@pytest.fixture
def kb_env():
    """Create a KnowledgeBase with temp dirs for both session and global KB."""
    tmpdir = tempfile.mkdtemp()
    global_dir = os.path.join(tmpdir, "global")
    os.makedirs(global_dir)

    import knowledge_base as kb_mod

    orig_kb_path = kb_mod.KB_PATH
    orig_global_path = kb_mod.GLOBAL_KB_PATH
    kb_mod.KB_PATH = tmpdir
    kb_mod.GLOBAL_KB_PATH = global_dir

    kb = kb_mod.KnowledgeBase(session_id="test_session")

    yield kb, tmpdir, global_dir

    kb_mod.KB_PATH = orig_kb_path
    kb_mod.GLOBAL_KB_PATH = orig_global_path
    shutil.rmtree(tmpdir, ignore_errors=True)


class TestGlobalKB:
    def test_save_global_finding(self, kb_env):
        kb, tmpdir, global_dir = kb_env
        result = kb.save_global_finding(
            "Test global finding", ["test"], dedup_key="test-1"
        )
        assert result is not None
        assert result["dedup_key"] == "test-1"

        # Verify written to file
        with open(kb.global_findings_path) as f:
            lines = [l for l in f if l.strip()]
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["description"] == "Test global finding"

    def test_global_dedup(self, kb_env):
        kb, _, _ = kb_env
        r1 = kb.save_global_finding("First", ["test"], dedup_key="dup-1")
        r2 = kb.save_global_finding("Second", ["test"], dedup_key="dup-1")

        assert r1 is not None
        assert r2 is None  # Duplicate, skipped

        # Only one entry in file
        with open(kb.global_findings_path) as f:
            lines = [l for l in f if l.strip()]
        assert len(lines) == 1

    def test_get_global_findings(self, kb_env):
        kb, _, _ = kb_env
        kb.save_global_finding("Finding A", ["crash"], dedup_key="a")
        kb.save_global_finding("Finding B", ["web_sourced"], dedup_key="b")
        kb.save_global_finding("Finding C", ["crash", "web_sourced"], dedup_key="c")

        all_findings = kb.get_global_findings()
        assert len(all_findings) == 3

        crash_findings = kb.get_global_findings(tag="crash")
        assert len(crash_findings) == 2

        web_findings = kb.get_global_findings(tag="web_sourced")
        assert len(web_findings) == 2

    def test_get_global_findings_limit(self, kb_env):
        kb, _, _ = kb_env
        for i in range(10):
            kb.save_global_finding(f"Finding {i}", ["test"], dedup_key=f"limit-{i}")

        limited = kb.get_global_findings(limit=3)
        assert len(limited) == 3
        # Should return the last 3
        assert "Finding 7" in limited[0]["description"]

    def test_auto_promote_web_sourced(self, kb_env):
        kb, _, _ = kb_env
        kb.save_finding(
            "Web CVE finding", tags=["web_sourced", "rrc"], dedup_key="CVE-2023-99999"
        )

        # Should be in both session and global
        session_findings = kb.query_findings(tag="web_sourced")
        assert len(session_findings) == 1

        global_findings = kb.get_global_findings(tag="web_sourced")
        assert len(global_findings) == 1
        assert global_findings[0]["dedup_key"] == "CVE-2023-99999"

    def test_auto_promote_without_dedup_key(self, kb_env):
        kb, _, _ = kb_env
        kb.save_finding("Web finding no key", tags=["web_sourced"])

        global_findings = kb.get_global_findings()
        assert len(global_findings) == 1
        # Should have auto-generated dedup_key
        assert global_findings[0]["dedup_key"].startswith("finding:")

    def test_promote_finding(self, kb_env):
        kb, _, _ = kb_env
        # Save a session finding (not web_sourced)
        kb.save_finding("Important discovery", tags=["crash", "rrc"])

        # Promote it
        result = kb.promote_finding(1)
        assert result is not None

        global_findings = kb.get_global_findings()
        assert len(global_findings) == 1
        assert "Important discovery" in global_findings[0]["description"]

    def test_promote_nonexistent_finding(self, kb_env):
        kb, _, _ = kb_env
        result = kb.promote_finding(999)
        assert result is None

    def test_promote_dedup(self, kb_env):
        kb, _, _ = kb_env
        kb.save_finding("Discovery X", tags=["rrc"])
        kb.promote_finding(1)
        kb.promote_finding(1)  # Should be deduped

        global_findings = kb.get_global_findings()
        assert len(global_findings) == 1

    def test_cross_session_global_persistence(self, kb_env):
        kb1, tmpdir, global_dir = kb_env
        kb1.save_global_finding("Session 1 finding", ["crash"], dedup_key="cross-1")

        # Create a new KB for a different session, same global dir
        import knowledge_base as kb_mod

        kb2 = kb_mod.KnowledgeBase(session_id="session_2")

        # kb2 should see kb1's global findings
        global_findings = kb2.get_global_findings()
        assert len(global_findings) == 1
        assert "Session 1 finding" in global_findings[0]["description"]

        # kb2 should also know the dedup key
        assert "cross-1" in kb2._global_dedup_keys

    def test_dedup_keys_loaded_at_init(self, kb_env):
        kb, tmpdir, global_dir = kb_env
        kb.save_global_finding("Pre-existing", ["test"], dedup_key="preload-1")

        # Create new KB instance — should load dedup keys
        import knowledge_base as kb_mod

        kb2 = kb_mod.KnowledgeBase(session_id="dedup_load_test")
        assert "preload-1" in kb2._global_dedup_keys
