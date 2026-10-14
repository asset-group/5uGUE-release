"""Extended KnowledgeBase tests: log_test, _append_crash_csv, rebuild_crashes_csv, persistence."""

import csv
import json
import os
import shutil
import tempfile
from unittest.mock import patch

import pytest


def _make_test_result(**overrides):
    """Create a TestResult with sensible defaults."""
    from execution_engine import TestResult

    defaults = dict(
        test_id="run-1",
        fuzz_description="test mutation",
        compile_success=True,
        compile_error=None,
        execution_time_seconds=45.0,
        crash_triggered=False,
        crash_id=None,
        crash_category="",
        crash_summary=None,
        exploit_name="mac_sch_test",
        exploit_code='#include "ModulesInclude.hpp"',
        new_states=[],
        new_transitions=[],
        capture_path="/tmp/capture.pcapng",
        log_path="/tmp/logs/test_run-1",
        total_packets=50,
        exploit_hash="abc123def456",
        mutation_count=3,
        mutation_log_lines=["[M] TX --> pkt1"],
    )
    defaults.update(overrides)
    return TestResult(**defaults)


def _make_kb(tmpdir, session_id="test_session"):
    """Create a KnowledgeBase with KB_PATH patched to tmpdir."""
    from knowledge_base import KnowledgeBase

    global_dir = os.path.join(tmpdir, "global")
    with (
        patch("knowledge_base.KB_PATH", tmpdir),
        patch("knowledge_base.GLOBAL_KB_PATH", global_dir),
    ):
        return KnowledgeBase(session_id)


@pytest.fixture
def tmp_kb_dir():
    tmpdir = tempfile.mkdtemp()
    yield tmpdir
    shutil.rmtree(tmpdir, ignore_errors=True)


class TestLogTest:
    def test_log_test_writes_jsonl(self, tmp_kb_dir):
        kb = _make_kb(tmp_kb_dir)
        tr = _make_test_result()
        kb.log_test(tr, "test mutation of RRC")

        assert os.path.exists(kb.tests_path)
        with open(kb.tests_path, "r") as f:
            lines = [l.strip() for l in f if l.strip()]
        assert len(lines) == 1

        entry = json.loads(lines[0])
        assert entry["test_id"] == "run-1"
        assert entry["exploit_name"] == "mac_sch_test"
        assert entry["crash"] is False
        assert entry["mutation_count"] == 3
        assert entry["total_packets"] == 50
        assert entry["compile_success"] is True
        assert entry["fuzz_description"] == "test mutation of RRC"
        assert "timestamp" in entry

    def test_log_test_increments_count(self, tmp_kb_dir):
        kb = _make_kb(tmp_kb_dir)
        assert kb.test_count == 0
        kb.log_test(_make_test_result(test_id="t1"), "desc1")
        assert kb.test_count == 1
        kb.log_test(_make_test_result(test_id="t2"), "desc2")
        assert kb.test_count == 2

    def test_log_test_adds_hash(self, tmp_kb_dir):
        kb = _make_kb(tmp_kb_dir)
        tr = _make_test_result(exploit_hash="hash_xyz")
        assert not kb.has_been_tested("hash_xyz")
        kb.log_test(tr, "desc")
        assert kb.has_been_tested("hash_xyz")

    def test_log_test_empty_hash_not_tracked(self, tmp_kb_dir):
        kb = _make_kb(tmp_kb_dir)
        tr = _make_test_result(exploit_hash="")
        kb.log_test(tr, "desc")
        assert not kb.has_been_tested("")

    def test_log_test_multiple_entries(self, tmp_kb_dir):
        kb = _make_kb(tmp_kb_dir)
        for i in range(5):
            kb.log_test(
                _make_test_result(test_id=f"t{i}", exploit_hash=f"h{i}"), f"desc{i}"
            )

        history = kb.get_test_history()
        assert len(history) == 5
        assert history[0]["test_id"] == "t0"
        assert history[4]["test_id"] == "t4"

    def test_get_test_history_respects_limit(self, tmp_kb_dir):
        kb = _make_kb(tmp_kb_dir)
        for i in range(10):
            kb.log_test(
                _make_test_result(test_id=f"t{i}", exploit_hash=f"h{i}"), f"desc{i}"
            )

        history = kb.get_test_history(limit=3)
        assert len(history) == 3
        assert history[0]["test_id"] == "t7"
        assert history[2]["test_id"] == "t9"


class TestAppendCrashCsv:
    def test_crash_creates_csv(self, tmp_kb_dir):
        crashes_csv = os.path.join(tmp_kb_dir, "crashes.csv")
        kb = _make_kb(tmp_kb_dir)

        tr = _make_test_result(
            crash_triggered=True,
            crash_id="CRASH_001",
            crash_category="fully_novel_crash",
            crash_summary="sModemReason=FATAL",
        )
        with patch("knowledge_base.CRASHES_CSV", crashes_csv):
            kb.log_test(tr, "crash mutation")

        assert os.path.exists(crashes_csv)
        with open(crashes_csv, "r") as f:
            reader = csv.reader(f)
            rows = list(reader)

        # Header + 1 data row
        assert len(rows) == 2
        header = rows[0]
        assert "timestamp" in header
        assert "crash_id" in header
        assert "replay_command" in header

        data = rows[1]
        assert "CRASH_001" in data
        assert "mac_sch_test" in data

    def test_no_csv_without_crash(self, tmp_kb_dir):
        crashes_csv = os.path.join(tmp_kb_dir, "crashes.csv")
        kb = _make_kb(tmp_kb_dir)

        tr = _make_test_result(crash_triggered=False)
        with patch("knowledge_base.CRASHES_CSV", crashes_csv):
            kb.log_test(tr, "no crash")

        assert not os.path.exists(crashes_csv)

    def test_multiple_crashes_append(self, tmp_kb_dir):
        crashes_csv = os.path.join(tmp_kb_dir, "crashes.csv")
        kb = _make_kb(tmp_kb_dir)

        with patch("knowledge_base.CRASHES_CSV", crashes_csv):
            for i in range(3):
                tr = _make_test_result(
                    test_id=f"t{i}",
                    exploit_hash=f"h{i}",
                    crash_triggered=True,
                    crash_id=f"CRASH_{i}",
                    crash_category="fully_novel_crash" if i == 0 else "",
                )
                kb.log_test(tr, f"crash {i}")

        with open(crashes_csv, "r") as f:
            reader = csv.reader(f)
            rows = list(reader)

        # Header + 3 data rows
        assert len(rows) == 4

    def test_crash_csv_replay_command(self, tmp_kb_dir):
        crashes_csv = os.path.join(tmp_kb_dir, "crashes.csv")
        kb = _make_kb(tmp_kb_dir)

        tr = _make_test_result(
            crash_triggered=True,
            crash_id="CRASH_X",
            exploit_name="mac_sch_fuzz1",
        )
        with patch("knowledge_base.CRASHES_CSV", crashes_csv):
            kb.log_test(tr, "test")

        with open(crashes_csv, "r") as f:
            content = f.read()
        assert "mac_sch_fuzz1" in content
        assert "--exploit=mac_sch_fuzz1" in content


class TestRebuildCrashesCsv:
    def test_rebuild_from_sessions(self, tmp_kb_dir):
        """rebuild_crashes_csv should aggregate crashes from all session tests.jsonl files."""
        from knowledge_base import KnowledgeBase

        crashes_csv = os.path.join(tmp_kb_dir, "rebuilt_crashes.csv")

        # Create two fake session dirs with tests.jsonl
        for session in ["session_a", "session_b"]:
            session_dir = os.path.join(tmp_kb_dir, session)
            os.makedirs(session_dir)
            tests_path = os.path.join(session_dir, "tests.jsonl")
            with open(tests_path, "w") as f:
                f.write(
                    json.dumps(
                        {
                            "test_id": f"{session}-1",
                            "exploit_name": "mac_sch_ok",
                            "crash": False,
                            "timestamp": "2026-01-01T00:00:00",
                        }
                    )
                    + "\n"
                )
                f.write(
                    json.dumps(
                        {
                            "test_id": f"{session}-2",
                            "exploit_name": "mac_sch_crash",
                            "crash": True,
                            "crash_category": "fully_novel_crash",
                            "crash_id": f"CRASH_{session}",
                            "mutation_count": 2,
                            "total_packets": 40,
                            "fuzz_description": f"crash in {session}",
                            "timestamp": "2026-01-01T01:00:00",
                        }
                    )
                    + "\n"
                )

        # rebuild_crashes_csv does its own import of constants, so we patch there
        with (
            patch("knowledge_base.KB_PATH", tmp_kb_dir),
            patch("knowledge_base.CRASHES_CSV", crashes_csv),
            patch("constants.KB_PATH", tmp_kb_dir),
            patch("constants.CRASHES_CSV", crashes_csv),
            patch("constants.EXPLOIT_FOLDER", tmp_kb_dir),
        ):
            KnowledgeBase.rebuild_crashes_csv()

        assert os.path.exists(crashes_csv)
        with open(crashes_csv, "r") as f:
            reader = csv.reader(f)
            rows = list(reader)

        # Header + 2 crash rows (one from each session)
        assert len(rows) == 3
        data_rows = rows[1:]
        crash_ids = [r[5] for r in data_rows]
        assert "CRASH_session_a" in crash_ids
        assert "CRASH_session_b" in crash_ids

    def test_rebuild_empty_kb(self, tmp_kb_dir):
        """Rebuild with no sessions should produce no CSV."""
        from knowledge_base import KnowledgeBase

        crashes_csv = os.path.join(tmp_kb_dir, "empty_crashes.csv")

        with (
            patch("knowledge_base.KB_PATH", tmp_kb_dir),
            patch("knowledge_base.CRASHES_CSV", crashes_csv),
            patch("constants.KB_PATH", tmp_kb_dir),
            patch("constants.CRASHES_CSV", crashes_csv),
        ):
            KnowledgeBase.rebuild_crashes_csv()

        assert not os.path.exists(crashes_csv)


class TestKnowledgeBasePersistence:
    def test_full_persistence_with_log_test(self, tmp_kb_dir):
        """KB should recover test hashes and counts after re-initialization."""
        kb1 = _make_kb(tmp_kb_dir, "persist_test")
        kb1.log_test(_make_test_result(test_id="t1", exploit_hash="hash1"), "desc1")
        kb1.log_test(_make_test_result(test_id="t2", exploit_hash="hash2"), "desc2")
        kb1.save_finding("important finding", tags=["crash"])
        kb1.update_strategy("focus on RRC")

        assert kb1.test_count == 2
        assert kb1.has_been_tested("hash1")
        assert kb1.has_been_tested("hash2")

        # Re-create from same session
        kb2 = _make_kb(tmp_kb_dir, "persist_test")
        assert kb2.test_count == 2
        assert kb2.has_been_tested("hash1")
        assert kb2.has_been_tested("hash2")
        assert not kb2.has_been_tested("hash3")
        assert len(kb2.query_findings()) == 1
        assert kb2.get_strategy() == "focus on RRC"
        assert len(kb2.get_test_history()) == 2

    def test_finding_count_persists(self, tmp_kb_dir):
        kb1 = _make_kb(tmp_kb_dir, "find_test")
        kb1.save_finding("f1", tags=["a"])
        kb1.save_finding("f2", tags=["b"])
        assert kb1._finding_count == 2

        kb2 = _make_kb(tmp_kb_dir, "find_test")
        assert kb2._finding_count == 2

        entry = kb2.save_finding("f3", tags=["c"])
        assert entry["finding_id"] == 3


class TestQueryFindings:
    def test_query_by_tag_and_field(self, tmp_kb_dir):
        kb = _make_kb(tmp_kb_dir, "query_test")
        kb.save_finding("RRC setup crash at offset 63", tags=["crash", "rrc"])
        kb.save_finding("NAS auth timeout observed", tags=["anomaly", "nas"])
        kb.save_finding("RLC type confusion at D/C bit", tags=["crash", "rlc"])

        crashes = kb.query_findings(tag="crash")
        assert len(crashes) == 2

        rrc = kb.query_findings(field="RRC")
        assert len(rrc) == 1
        assert "offset 63" in rrc[0]["description"]

        crash_rlc = kb.query_findings(tag="crash", field="D/C")
        assert len(crash_rlc) == 1

        empty = kb.query_findings(tag="nonexistent")
        assert len(empty) == 0


class TestStrategyOperations:
    def test_overwrite_strategy(self, tmp_kb_dir):
        kb = _make_kb(tmp_kb_dir, "strat_test")
        kb.update_strategy("Plan A")
        assert kb.get_strategy() == "Plan A"
        kb.update_strategy("Plan B")
        assert kb.get_strategy() == "Plan B"

    def test_multiline_strategy(self, tmp_kb_dir):
        kb = _make_kb(tmp_kb_dir, "strat_ml")
        strategy = "# Strategy\n- Focus on RRC\n- Try truncation\n- Explore RLC"
        kb.update_strategy(strategy)
        assert kb.get_strategy() == strategy


class TestQueryFindingsPastSessions:
    """Test query_findings behavior with include_past_sessions across session directories."""

    def test_query_findings_default_past_sessions_false(self, tmp_kb_dir):
        from knowledge_base import KnowledgeBase

        global_dir = os.path.join(tmp_kb_dir, "global")
        past_dir = os.path.join(tmp_kb_dir, "past_session_01")
        os.makedirs(past_dir, exist_ok=True)
        with open(os.path.join(past_dir, "findings.jsonl"), "w") as f:
            f.write(
                json.dumps(
                    {
                        "finding_id": 1,
                        "description": "Past finding",
                        "tags": ["crash"],
                    }
                )
                + "\n"
            )

        with (
            patch("knowledge_base.KB_PATH", tmp_kb_dir),
            patch("knowledge_base.GLOBAL_KB_PATH", global_dir),
        ):
            kb = KnowledgeBase("current_session")
            # Default call should return empty (only current session)
            assert kb.query_findings() == []

            # Explicit include_past_sessions=True should return past finding
            res = kb.query_findings(include_past_sessions=True)
            assert len(res) == 1
            assert res[0]["description"] == "Past finding"

    def test_query_findings_chronological_mtime_sorting(self, tmp_kb_dir):
        from knowledge_base import KnowledgeBase

        global_dir = os.path.join(tmp_kb_dir, "global")
        s1 = os.path.join(tmp_kb_dir, "session_older")
        s2 = os.path.join(tmp_kb_dir, "session_newer")
        os.makedirs(s1, exist_ok=True)
        os.makedirs(s2, exist_ok=True)

        with open(os.path.join(s1, "findings.jsonl"), "w") as f:
            f.write(
                json.dumps(
                    {"description": "Old observation 1", "tags": ["rrc"]}
                )
                + "\n"
            )
        os.utime(s1, (1000, 1000))

        with open(os.path.join(s2, "findings.jsonl"), "w") as f:
            f.write(
                json.dumps(
                    {"description": "New observation 2", "tags": ["rrc"]}
                )
                + "\n"
            )
        os.utime(s2, (2000, 2000))

        with (
            patch("knowledge_base.KB_PATH", tmp_kb_dir),
            patch("knowledge_base.GLOBAL_KB_PATH", global_dir),
        ):
            kb = KnowledgeBase("session_current")
            res = kb.query_findings(include_past_sessions=True, limit=1)
            assert len(res) == 1
            assert res[0]["description"] == "New observation 2"

    def test_query_findings_filter_before_dedup(self, tmp_kb_dir):
        from knowledge_base import KnowledgeBase

        global_dir = os.path.join(tmp_kb_dir, "global")
        s1 = os.path.join(tmp_kb_dir, "session_01")
        s2 = os.path.join(tmp_kb_dir, "session_02")
        os.makedirs(s1, exist_ok=True)
        os.makedirs(s2, exist_ok=True)

        with open(os.path.join(s1, "findings.jsonl"), "w") as f:
            f.write(
                json.dumps(
                    {
                        "description": "Shared finding",
                        "tags": ["no_crash"],
                        "dedup_key": "k1",
                    }
                )
                + "\n"
            )
        os.utime(s1, (1000, 1000))

        with open(os.path.join(s2, "findings.jsonl"), "w") as f:
            f.write(
                json.dumps(
                    {
                        "description": "Shared finding",
                        "tags": ["crash"],
                        "dedup_key": "k1",
                    }
                )
                + "\n"
            )
        os.utime(s2, (2000, 2000))

        with (
            patch("knowledge_base.KB_PATH", tmp_kb_dir),
            patch("knowledge_base.GLOBAL_KB_PATH", global_dir),
        ):
            kb = KnowledgeBase("session_current")
            res = kb.query_findings(tag="crash", include_past_sessions=True)
            assert len(res) == 1
            assert "crash" in res[0]["tags"]

