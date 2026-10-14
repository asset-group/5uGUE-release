"""Unit and integration tests for evals/eval_research_quality.py.

Tests research quality evaluation, ground truth schema alignment, vendor device filtering
(e.g., mediatek, mediatek_d9400), L0-L5 scoring levels, and DB/session loaders.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

from evals.eval_research_quality import (
    GROUND_TRUTH_PATH,
    load_ground_truth,
    score_finding_against_entry,
    score_findings_text,
    score_session,
    score_session_db,
)

# ── Section A: Ground Truth Dataset & Key Filtering ──────────────────────────


class TestLoadGroundTruth:
    """Tests for ground truth benchmark loading and vendor device filtering."""

    def test_load_ground_truth_all_entries(self):
        """Verify calling load_ground_truth() with no arguments returns all benchmark entries."""
        with open(GROUND_TRUTH_PATH) as f:
            expected_total = len(json.load(f)["entries"])

        entries = load_ground_truth()
        assert len(entries) == expected_total
        assert expected_total > 0

    def test_load_ground_truth_filter_by_device(self):
        """Verify filtering for all valid device types: mediatek, mediatek_d9400."""
        valid_devices = ["mediatek", "mediatek_d9400"]

        for device in valid_devices:
            entries = load_ground_truth(device=device)
            # Ensure filtering returned non-empty results for supported devices
            assert len(entries) > 0, f"Expected non-empty entries for device '{device}'"
            # Ensure every returned entry matches the filtered device key
            for entry in entries:
                assert entry.get("device") == device

    def test_load_ground_truth_unrecognized_device(self):
        """Verify requesting a non-existent device returns an empty list safely."""
        entries = load_ground_truth(device="nonexistent_vendor_device")
        assert entries == []

    def test_ground_truth_json_schema_validation(self):
        """Schema test: Ensure every entry in ground_truth.json contains required fields.

        Checks that 'device' is correctly set to one of the expected vendor names
        (preventing regressions like using 'modem' instead of 'device').
        """
        allowed_devices = {"mediatek", "mediatek_d9400"}
        required_fields = {"eval_id", "crash_name", "expected_extractions", "device"}

        with open(GROUND_TRUTH_PATH) as f:
            data = json.load(f)["entries"]

        for entry in data:
            for field in required_fields:
                assert field in entry, (
                    f"Entry {entry.get('eval_id')} missing key '{field}'"
                )
            assert entry["device"] in allowed_devices, (
                f"Entry {entry['eval_id']} has unexpected device '{entry['device']}'"
            )


# ── Section B: Finding-Level Evaluation (score_finding_against_entry) ───────


class TestScoreFindingAgainstEntry:
    """Unit tests for finding-level text matching against ground truth entries (L0 to L4)."""

    @pytest.fixture
    def sample_entry(self):
        """Sample ground truth entry for 5Ghoul RRC Setup crash 1 (MediaTek)."""
        return {
            "eval_id": "5ghoul_rrc_setup_crash_1",
            "device": "mediatek",
            "expected_extractions": {
                "filter": "nr-rrc.rrcSetup_element",
                "offsets": [63],
                "values": ["0x5b"],
                "field": "searchSpacesToAddModList",
            },
        }

    def test_score_finding_against_entry_l0(self, sample_entry):
        """Unrelated text with no CVE/vulnerability keywords should score L0 (0)."""
        text = "System initialized and waiting for incoming connection packets."
        assert score_finding_against_entry(text, sample_entry) == 0

    def test_score_finding_against_entry_l1(self, sample_entry):
        """Text naming the project or CVE (e.g. '5ghoul') should score L1 (1)."""
        text = "Observed potential issue related to 5ghoul advisory."
        assert score_finding_against_entry(text, sample_entry) == 1

    def test_score_finding_against_entry_l2(self, sample_entry):
        """Text identifying the correct message type (e.g. 'RRC Setup') should score L2 (2)."""
        text = "5ghoul attack targets RRC Setup message processing."
        assert score_finding_against_entry(text, sample_entry) == 2

    def test_score_finding_against_entry_l3(self, sample_entry):
        """Text identifying correct substructure (e.g. 'searchspace') should score L3 (3)."""
        text = "5ghoul vulnerability in RRC Setup message near searchspace element."
        assert score_finding_against_entry(text, sample_entry) == 3

    def test_score_finding_against_entry_l4(self, sample_entry):
        """Text with exact byte offset and value (e.g. offset 63, 0x5b) should score L4 (4)."""
        text = (
            "5ghoul vulnerability in RRC Setup message near searchspace element. "
            "Byte mutation at offset 63 set to 0x5b."
        )
        assert score_finding_against_entry(text, sample_entry) == 4


# ── Section C: Public Text Scorer (score_findings_text) ──────────────────────


class TestScoreFindingsText:
    """Tests for the public score_findings_text helper function."""

    def test_score_findings_text_basic(self):
        """Verify score_findings_text scores raw finding text across ground-truth benchmarks."""
        text = "5ghoul exploit targets RRC Setup message with searchspace at offset 63, value 0x5b"
        result = score_findings_text(text)

        assert "max_score" in result
        assert "mean_score" in result
        assert "per_entry" in result
        assert result["max_score"] >= 4

    def test_score_findings_text_device_filter(self):
        """Verify passing a device filter only scores against entries for that device."""
        text = "5ghoul exploit targets RRC Setup message"
        result = score_findings_text(text, device="mediatek")

        mediatek_gt = load_ground_truth(device="mediatek")
        mediatek_ids = {e["eval_id"] for e in mediatek_gt}

        # Verify evaluated entries match exactly the MediaTek ground-truth benchmark IDs
        assert set(result["per_entry"].keys()) == mediatek_ids


# ── Section D: Session & Post-Hoc Crash Scoring (score_session) ───────────────


class TestScoreSession:
    """Integration tests for directory-based session scoring."""

    def test_score_session_with_device_filter(self, tmp_path):
        """Verify score_session correctly loads findings and applies device filter."""
        findings_file = tmp_path / "findings.jsonl"
        finding_data = {
            "description": "5ghoul exploit targets RRC Setup searchspace at offset 63 value 0x5b"
        }
        findings_file.write_text(json.dumps(finding_data) + "\n")

        result = score_session(str(tmp_path), device="mediatek")
        assert result["max_score"] >= 4
        assert len(result["per_entry"]) > 0

    def test_score_session_l5_crash_upgrade(self, tmp_path):
        """Verify L5 upgrade logic: base score >= 4 + matching crash in tests.jsonl = L5 (5).

        L5 is a post-hoc score upgrade evaluated during score_session if a crash signature
        matching ground truth (e.g. 'nr_slm_rpt_hndlr.c line:9302') is found in tests.jsonl.
        """
        # Write finding reaching L4
        findings_file = tmp_path / "findings.jsonl"
        finding_data = {
            "description": "5ghoul vulnerability in RRC Setup searchspace at offset 63 set to 0x5b"
        }
        findings_file.write_text(json.dumps(finding_data) + "\n")

        # Write test log with matching crash signature for 5ghoul_rrc_setup_crash_1
        tests_file = tmp_path / "tests.jsonl"
        test_data = {
            "crash": True,
            "crash_id": "nr_slm_rpt_hndlr.c line:9302 assert triggered",
        }
        tests_file.write_text(json.dumps(test_data) + "\n")

        result = score_session(str(tmp_path), device="mediatek")
        assert result["per_entry"]["5ghoul_rrc_setup_crash_1"]["score"] == 5, (
            "Expected score to be upgraded to L5 (5) due to verified crash signature"
        )


# ── Section E: Database Session Scoring (score_session_db) ───────────────────


class TestScoreSessionDb:
    """Tests for database-backed session scoring (score_session_db)."""

    @patch("dashboard.db.get_pool")
    def test_score_session_db_with_mock_db(self, mock_get_pool):
        """Verify score_session_db with mocked database session records."""
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_get_pool.return_value.connection.return_value.__enter__.return_value = (
            mock_conn
        )
        mock_conn.cursor.return_value.__enter__.return_value = mock_cur

        # Mock findings and crash query responses
        mock_cur.fetchall.side_effect = [
            # First query: findings
            [
                {
                    "description": "5ghoul exploit targets RRC Setup searchspace offset 63 value 0x5b"
                }
            ],
            # Second query: tests/crashes
            [{"crash_id": "nr_slm_rpt_hndlr.c line:9302"}],
        ]

        result = score_session_db("session_cb408c1b", device="mediatek")
        assert result["max_score"] == 5
        assert result["per_entry"]["5ghoul_rrc_setup_crash_1"]["score"] == 5
        mock_get_pool.assert_called_once()
        first_call_sql = mock_cur.execute.call_args_list[0][0][0]
        assert "ORDER BY finding_id" in first_call_sql

    @patch("dashboard.db.get_pool")
    def test_score_session_db_sql_ordering(self, mock_get_pool):
        """Verify that score_session_db queries session_finding ordered by finding_id."""
        mock_conn = MagicMock()
        mock_cur = MagicMock()
        mock_get_pool.return_value.connection.return_value.__enter__.return_value = (
            mock_conn
        )
        mock_conn.cursor.return_value.__enter__.return_value = mock_cur

        mock_cur.fetchall.side_effect = [
            [],
            [],
        ]

        score_session_db("test_session_id")
        sql_executed = mock_cur.execute.call_args_list[0][0][0]
        assert "ORDER BY finding_id" in sql_executed


# ── Section F: Negative & Edge Cases ──────────────────────────────────────────


class TestNegativeAndEdgeCases:
    """Negative tests for edge cases, missing files, and invalid parameters."""

    def test_score_session_empty_findings(self, tmp_path):
        """Verify an empty findings.jsonl file returns 0 max_score gracefully."""
        findings_file = tmp_path / "findings.jsonl"
        findings_file.write_text("\n\n")

        result = score_session(str(tmp_path))
        assert result["max_score"] == 0

    def test_score_session_missing_tests_jsonl(self, tmp_path):
        """Verify score_session works when tests.jsonl is absent (scores up to L4)."""
        findings_file = tmp_path / "findings.jsonl"
        finding_data = {
            "description": "5ghoul vulnerability in RRC Setup searchspace at offset 63 set to 0x5b"
        }
        findings_file.write_text(json.dumps(finding_data) + "\n")

        # tests.jsonl is intentionally NOT created
        result = score_session(str(tmp_path), device="mediatek")
        assert result["max_score"] == 4

    def test_score_session_nonexistent_directory(self):
        """Verify passing a non-existent session_dir handles missing findings.jsonl safely.

        Checks the actual implementation behavior: os.path.exists(findings_path) evaluates to False,
        returning {'error': 'No findings.jsonl in ...', 'max_score': 0} without an exception.
        """
        non_existent_dir = "/nonexistent/path/to/session_12345"
        result = score_session(non_existent_dir)

        assert "error" in result
        assert result["max_score"] == 0
        assert non_existent_dir in result["error"]

    def test_score_session_unmatched_device_filter(self, tmp_path):
        """Verify passing an unrecognized device filter returns 0 entries evaluated."""
        findings_file = tmp_path / "findings.jsonl"
        findings_file.write_text(json.dumps({"description": "5ghoul exploit"}) + "\n")

        result = score_session(str(tmp_path), device="nonexistent_device")
        assert len(result["per_entry"]) == 0
        assert result["max_score"] == 0
