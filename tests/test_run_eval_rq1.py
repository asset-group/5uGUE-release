"""Unit tests for rq_scripts/run_eval_rq1.py."""

import csv
import json
import os
import tempfile

import pytest

# Import the module under test
from rq_scripts.run_eval_rq1 import (
    parse_run_id_from_output,
    find_new_manifest,
    extract_metrics_from_file,
    build_csv_row,
    write_csv,
    CSV_COLUMNS,
)


# ── parse_run_id_from_output ─────────────────────────────────────────────────


class TestParseRunId:
    def test_normal_log_output(self):
        output = (
            "2026-03-26 10:00:00 [INFO] run_agent.py:70: Run ID: ab12cd34\n"
            "2026-03-26 10:00:01 [INFO] run_agent.py:71: Session: ab12cd34-rq1-v1\n"
        )
        assert parse_run_id_from_output(output) == "ab12cd34"

    def test_no_run_id_in_output(self):
        assert parse_run_id_from_output("some random log output") is None

    def test_empty_output(self):
        assert parse_run_id_from_output("") is None

    def test_malformed_run_id_too_short(self):
        output = "Run ID: ab12"
        assert parse_run_id_from_output(output) is None

    def test_run_id_with_surrounding_text(self):
        output = "blah blah Run ID: deadbeef more stuff"
        assert parse_run_id_from_output(output) == "deadbeef"

    def test_multiple_run_ids_takes_first(self):
        output = "Run ID: aaaaaaaa\nRun ID: bbbbbbbb\n"
        assert parse_run_id_from_output(output) == "aaaaaaaa"


# ── find_new_manifest (fallback) ─────────────────────────────────────────────


class TestFindNewManifest:
    def test_finds_new_manifest(self, tmp_path, monkeypatch):
        # Create a "before" manifest
        before_manifest = tmp_path / "old_manifest.json"
        before_manifest.write_text("{}")
        before_set = {str(before_manifest)}

        # Create a "new" manifest
        new_manifest = tmp_path / "new_manifest.json"
        new_manifest.write_text('{"run_id": "abcd1234"}')

        # Monkeypatch _list_manifest_files to return both
        import rq_scripts.run_eval_rq1 as mod

        monkeypatch.setattr(
            mod,
            "_list_manifest_files",
            lambda: [str(before_manifest), str(new_manifest)],
        )

        result = find_new_manifest(before_set)
        assert result == str(new_manifest)

    def test_no_new_manifests(self, monkeypatch):
        before = {"/some/path/old_manifest.json"}
        import rq_scripts.run_eval_rq1 as mod

        monkeypatch.setattr(
            mod, "_list_manifest_files", lambda: ["/some/path/old_manifest.json"]
        )
        assert find_new_manifest(before) is None


# ── extract_metrics_from_file ────────────────────────────────────────────────


class TestExtractMetrics:
    def test_normal_jsonl(self, tmp_path):
        metrics_file = tmp_path / "agent_metrics_test.jsonl"
        records = [
            {
                "turn": 1,
                "timestamp": 1000.0,
                "session_start_time": 1000.0,
                "cumulative_crashes": 1,
                "cumulative_publicly_known": 1,
                "cumulative_non_publicly_known": 0,
                "cumulative_fully_novel": 0,
                "cumulative_input_tokens": 5000,
                "cumulative_output_tokens": 1000,
                "session_unique_crashes": 1,
                "session_unique_novel_crashes": 0,
                "cumulative_test_count": 4,
                "first_crash_test_count": 3,
                "first_crash_timestamp": 1004.5,
            },
            {
                "turn": 2,
                "timestamp": 1010.5,
                "session_start_time": 1000.0,
                "cumulative_crashes": 3,
                "cumulative_publicly_known": 1,
                "cumulative_non_publicly_known": 2,
                "cumulative_fully_novel": 1,
                "cumulative_input_tokens": 12000,
                "cumulative_output_tokens": 3000,
                "session_unique_crashes": 2,
                "session_unique_novel_crashes": 1,
                "cumulative_test_count": 9,
                "first_crash_test_count": 3,
                "first_crash_timestamp": 1004.5,
            },
        ]
        with open(metrics_file, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

        result = extract_metrics_from_file(str(metrics_file))
        assert result["actual_turns"] == 2
        assert result["cumulative_crashes"] == 3
        assert result["cumulative_publicly_known"] == 1
        assert result["cumulative_non_publicly_known"] == 2
        assert result["cumulative_fully_novel"] == 1
        assert result["cumulative_input_tokens"] == 12000
        assert result["cumulative_output_tokens"] == 3000
        assert result["unique_crashes"] == 2
        assert result["unique_novel"] == 1
        assert result["total_tests"] == 9
        assert result["total_session_time_seconds"] == 10.5
        assert result["time_to_first_crash_seconds"] == 4.5
        assert result["tests_till_first_crash"] == 3

    def test_no_crash_session(self, tmp_path):
        metrics_file = tmp_path / "agent_metrics_nocrash.jsonl"
        records = [
            {
                "turn": 1,
                "timestamp": 1000.0,
                "session_start_time": 1000.0,
                "cumulative_crashes": 0,
                "session_unique_crashes": 0,
                "session_unique_novel_crashes": 0,
                "cumulative_test_count": 2,
                "first_crash_test_count": None,
                "first_crash_timestamp": None,
            },
            {
                "turn": 2,
                "timestamp": 1007.25,
                "session_start_time": 1000.0,
                "cumulative_crashes": 0,
                "session_unique_crashes": 0,
                "session_unique_novel_crashes": 0,
                "cumulative_test_count": 5,
                "first_crash_test_count": None,
                "first_crash_timestamp": None,
            },
        ]
        with open(metrics_file, "w") as f:
            for r in records:
                f.write(json.dumps(r) + "\n")

        result = extract_metrics_from_file(str(metrics_file))
        assert result["unique_crashes"] == 0
        assert result["unique_novel"] == 0
        assert result["total_tests"] == 5
        assert result["total_session_time_seconds"] == 7.25
        assert result["time_to_first_crash_seconds"] == "N/A"
        assert result["tests_till_first_crash"] == "N/A"

    def test_missing_file(self):
        result = extract_metrics_from_file("/nonexistent/path.jsonl")
        assert result["actual_turns"] == 0
        assert result["cumulative_crashes"] == 0
        assert result["unique_crashes"] == 0
        assert result["unique_novel"] == 0
        assert result["total_tests"] == 0
        assert result["time_to_first_crash_seconds"] == "N/A"
        assert result["tests_till_first_crash"] == "N/A"
        assert result["total_session_time_seconds"] == 0.0

    def test_empty_file(self, tmp_path):
        metrics_file = tmp_path / "empty.jsonl"
        metrics_file.write_text("")
        result = extract_metrics_from_file(str(metrics_file))
        assert result["actual_turns"] == 0
        assert result["time_to_first_crash_seconds"] == "N/A"

    def test_corrupt_jsonl(self, tmp_path):
        metrics_file = tmp_path / "corrupt.jsonl"
        metrics_file.write_text("not valid json\n")
        result = extract_metrics_from_file(str(metrics_file))
        assert result["actual_turns"] == 0
        assert result["unique_crashes"] == 0
        assert result["unique_novel"] == 0


# ── build_csv_row ────────────────────────────────────────────────────────────


class TestBuildCsvRow:
    def test_complete_data(self):
        metrics = {
            "actual_turns": 30,
            "cumulative_publicly_known": 2,
            "cumulative_non_publicly_known": 5,
            "cumulative_fully_novel": 1,
            "cumulative_crashes": 8,
            "cumulative_input_tokens": 100000,
            "cumulative_output_tokens": 25000,
            "unique_crashes": 6,
            "unique_novel": 3,
            "total_tests": 47,
            "time_to_first_crash_seconds": 12.34,
            "tests_till_first_crash": 5,
            "total_session_time_seconds": 1234.56,
        }
        rq_scores = {"max_score": 4, "max_level": "L4", "mean_score": 2.5}

        row = build_csv_row(
            run_id="abcd1234",
            session_id="abcd1234-rq1-v1-20260326",
            model="anthropic/claude-sonnet-4.6",
            version="v1",
            max_turns=30,
            metrics=metrics,
            rq_scores=rq_scores,
        )

        assert row["run_id"] == "abcd1234"
        assert row["session_id"] == "abcd1234-rq1-v1-20260326"
        assert row["rq_max_score"] == 4
        assert row["rq_max_level"] == "L4"
        assert row["publicly_known_crashes"] == 2
        assert row["total_crashes"] == 8
        assert row["total_input_tokens"] == 100000
        assert row["unique_crashes"] == 6
        assert row["unique_novel"] == 3
        assert row["total_tests"] == 47
        assert row["time_to_first_crash_seconds"] == 12.34
        assert row["tests_till_first_crash"] == 5
        assert row["total_session_time_seconds"] == 1234.56

    def test_partial_failure_missing_run_id(self):
        row = build_csv_row(
            run_id=None,
            session_id=None,
            model="anthropic/claude-sonnet-4.6",
            version="v1",
            max_turns=30,
            metrics={},
            rq_scores={},
        )
        assert row["run_id"] == "N/A"
        assert row["session_id"] == "N/A"
        assert row["rq_max_score"] == 0
        assert row["rq_max_level"] == "L0"
        assert row["publicly_known_crashes"] == 0
        assert row["total_crashes"] == 0
        assert row["unique_crashes"] == 0
        assert row["unique_novel"] == 0
        assert row["total_tests"] == 0
        assert row["time_to_first_crash_seconds"] == "N/A"
        assert row["tests_till_first_crash"] == "N/A"
        assert row["total_session_time_seconds"] == 0.0

    def test_row_has_all_columns(self):
        row = build_csv_row("id", "sid", "model", "v1", 10, {}, {})
        assert set(row.keys()) == set(CSV_COLUMNS)

    def test_eval_id_is_first_column_and_propagates(self):
        assert CSV_COLUMNS[0] == "eval_id"
        eval_id = "0123456789abcdef0123456789abcdef"
        row = build_csv_row(
            "id",
            "sid",
            "model",
            "v1",
            10,
            {},
            {},
            eval_id=eval_id,
        )
        assert row["eval_id"] == eval_id

    def test_eval_id_shared_across_rows_in_csv(self, tmp_path):
        """All N rows in a single eval CSV share the same eval_id."""
        eval_id = "fedcba9876543210fedcba9876543210"
        rows = [
            build_csv_row(f"r{i}", f"s{i}", "m", "v3", 30, {}, {}, eval_id=eval_id)
            for i in range(3)
        ]
        out = str(tmp_path / "share.csv")
        write_csv(rows, out)
        with open(out) as f:
            reader = csv.DictReader(f)
            assert reader.fieldnames[0] == "eval_id"
            read_rows = list(reader)
        assert {r["eval_id"] for r in read_rows} == {eval_id}


# ── write_csv ────────────────────────────────────────────────────────────────


class TestWriteCsv:
    def test_writes_and_reads_back(self, tmp_path):
        rows = [
            build_csv_row(
                "aaa",
                "sid1",
                "model1",
                "v1",
                10,
                {
                    "actual_turns": 10,
                    "cumulative_crashes": 2,
                    "cumulative_publicly_known": 1,
                    "cumulative_non_publicly_known": 1,
                    "cumulative_fully_novel": 0,
                    "cumulative_input_tokens": 5000,
                    "cumulative_output_tokens": 1000,
                },
                {"max_score": 3, "max_level": "L3", "mean_score": 1.5},
            ),
            build_csv_row(
                "bbb",
                "sid2",
                "model1",
                "v2",
                20,
                {
                    "actual_turns": 18,
                    "cumulative_crashes": 5,
                    "cumulative_publicly_known": 2,
                    "cumulative_non_publicly_known": 2,
                    "cumulative_fully_novel": 1,
                    "cumulative_input_tokens": 15000,
                    "cumulative_output_tokens": 4000,
                },
                {"max_score": 4, "max_level": "L4", "mean_score": 2.8},
            ),
        ]

        output_path = str(tmp_path / "test_results.csv")
        write_csv(rows, output_path)

        # Read back
        with open(output_path) as f:
            reader = csv.DictReader(f)
            read_rows = list(reader)

        assert len(read_rows) == 2
        assert read_rows[0]["run_id"] == "aaa"
        assert read_rows[1]["run_id"] == "bbb"
        assert read_rows[0]["rq_max_level"] == "L3"
        assert read_rows[1]["total_crashes"] == "5"  # CSV reads as strings
        assert set(reader.fieldnames) == set(CSV_COLUMNS)

    def test_creates_parent_dirs(self, tmp_path):
        output_path = str(tmp_path / "nested" / "dir" / "results.csv")
        write_csv([], output_path)
        assert os.path.exists(output_path)
