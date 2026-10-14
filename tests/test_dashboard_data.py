"""Verify dashboard build data matches source artifacts (log files, JSONL)."""

import glob
import json
import os
import sys

import pytest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(TESTS_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from dashboard.data_loader import load_run_data, load_run_list

# Post-cutover, load_run_list() requires PG_DSN. Skip the whole module when
# the test environment has no DB configured — these tests are correctness
# checks for the live dashboard, not unit tests that should run in every CI.
if not os.environ.get("PG_DSN"):
    pytest.skip(
        "PG_DSN not set — skipping live dashboard data tests", allow_module_level=True
    )

LOG_PATH = os.path.join(AGENT_DIR, "logs")
KB_PATH = os.path.join(AGENT_DIR, "kb")
BUILD_DATA_DIR = os.path.join(AGENT_DIR, "dashboard", "build", "data", "runs")


def _available_run_ids():
    """Return run_ids that have both a KB dir and test log folders."""
    runs = load_run_list()
    ids = []
    for r in runs:
        rid = r["run_id"]
        kb_dirs = glob.glob(os.path.join(KB_PATH, f"{rid}-*"))
        log_dir = os.path.join(LOG_PATH, f"run_{rid}")
        if kb_dirs and os.path.isdir(log_dir):
            ids.append(rid)
    return ids


def _sample_run_ids(n=3):
    ids = _available_run_ids()
    # pick first, middle, last for coverage
    if len(ids) <= n:
        return ids
    step = max(1, (len(ids) - 1) // (n - 1))
    return [ids[i] for i in range(0, len(ids), step)][:n]


SAMPLE_RUNS = _sample_run_ids()


class TestExploitCodeMatchesLogFiles:
    """exploit_code in dashboard data must match the .cpp files in logs/run_*/test_*/."""

    @pytest.mark.parametrize("run_id", SAMPLE_RUNS)
    def test_exploit_code_matches_log_cpp(self, run_id):
        data = load_run_data(run_id)
        assert data is not None, f"load_run_data returned None for {run_id}"

        tests = data.get("tests", [])
        assert tests, f"No tests found for run {run_id}"

        matched = 0
        for t in tests:
            test_num = t["test_id"].split("-")[-1]
            exploit_name = t.get("exploit_name", "")
            cpp_path = os.path.join(
                LOG_PATH, f"run_{run_id}", f"test_{test_num}", f"{exploit_name}.cpp"
            )
            if not os.path.exists(cpp_path):
                continue

            with open(cpp_path) as f:
                file_code = f.read()

            jsonl_code = t.get("exploit_code", "")
            assert jsonl_code, f"exploit_code missing for test {t['test_id']}"
            assert file_code == jsonl_code, (
                f"Code mismatch for {t['test_id']} ({exploit_name}.cpp): "
                f"log file {len(file_code)} chars vs jsonl {len(jsonl_code)} chars"
            )
            matched += 1

        assert matched > 0, f"No .cpp files found in logs for run {run_id}"

    @pytest.mark.parametrize("run_id", SAMPLE_RUNS)
    def test_static_build_matches_source(self, run_id):
        """Static build JSON must contain the same exploit_code as source JSONL."""
        build_json = os.path.join(BUILD_DATA_DIR, f"{run_id}.json")
        if not os.path.exists(build_json):
            pytest.skip(f"No static build for {run_id} (run build_static.py first)")

        with open(build_json) as f:
            build_data = json.load(f)

        source_data = load_run_data(run_id)
        assert source_data is not None

        build_tests = {t["test_id"]: t for t in build_data.get("tests", [])}
        source_tests = {t["test_id"]: t for t in source_data.get("tests", [])}

        assert set(build_tests.keys()) == set(source_tests.keys()), "Test ID mismatch"

        for tid, src_test in source_tests.items():
            build_test = build_tests[tid]
            assert build_test.get("exploit_code") == src_test.get("exploit_code"), (
                f"exploit_code mismatch in static build for {tid}"
            )


class TestReasoningIntegrity:
    """Reasoning blocks in dashboard data must match the app log."""

    @pytest.mark.parametrize("run_id", SAMPLE_RUNS)
    def test_reasoning_not_empty_when_log_exists(self, run_id):
        data = load_run_data(run_id)
        assert data is not None

        from evals.resolve_run import resolve_run

        info = resolve_run(run_id)
        app_log = info.get("app_log", "")

        if app_log and os.path.exists(app_log):
            with open(app_log) as f:
                has_reasoning = any("[REASONING]" in line for line in f)
            if has_reasoning:
                assert data["reasoning"], (
                    f"App log has [REASONING] lines but dashboard data is empty for {run_id}"
                )

    @pytest.mark.parametrize("run_id", SAMPLE_RUNS)
    def test_reasoning_count_matches_log(self, run_id):
        """Number of reasoning blocks must match [REASONING] markers in app log."""
        from evals.resolve_run import resolve_run

        info = resolve_run(run_id)
        app_log = info.get("app_log", "")

        if not app_log or not os.path.exists(app_log):
            pytest.skip(f"No app log for {run_id}")

        with open(app_log) as f:
            log_count = sum(1 for line in f if "[REASONING]" in line)

        data = load_run_data(run_id)
        assert data is not None
        assert len(data["reasoning"]) == log_count, (
            f"Reasoning count mismatch: {len(data['reasoning'])} parsed vs {log_count} in log"
        )

    @pytest.mark.parametrize("run_id", SAMPLE_RUNS)
    def test_static_build_reasoning_matches_source(self, run_id):
        build_json = os.path.join(BUILD_DATA_DIR, f"{run_id}.json")
        if not os.path.exists(build_json):
            pytest.skip(f"No static build for {run_id}")

        with open(build_json) as f:
            build_data = json.load(f)

        source_data = load_run_data(run_id)
        assert source_data is not None

        build_r = build_data.get("reasoning", [])
        source_r = source_data.get("reasoning", [])
        assert len(build_r) == len(source_r), "Reasoning count mismatch in static build"

        for i, (b, s) in enumerate(zip(build_r, source_r)):
            assert b["content"] == s["content"], (
                f"Reasoning block #{i + 1} content mismatch in static build"
            )
