"""Tests for heatmap construction in dashboard.data_loader.load_sweep_data.

Covers the offset-axis selection logic: planned offsets vs. tested offsets,
including the drift-detection fallback that fixes sweeps whose `near_known`
plan can no longer be reproduced from the current crash DB.
"""

import glob
import json
import os
import sys

import pytest

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(TESTS_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

# Heatmap construction is identical in the SQL- and file-backed loaders;
# this test exercises the file-backed path so it can run without a DB.
from dashboard import data_loader_files as data_loader

plan_module = pytest.importorskip("sweep_scripts_202604.plan")

FILT = "nr-rrc.rrcSetup_element"
VALUES = [0x5B, 0xE1, 0xB6]


def _write_sweep(
    tmp_path, sid, tested_offsets, crash_offsets=(), fail_offsets=(), host="host_a"
):
    """Create a minimal sweep directory under tmp_path/<host>/<sid>/ and return it.

    The host-namespaced layout (sweep_logs/<host>/<sweep_id>/) is what the
    streaming-sync architecture writes; tests exercise that layout directly.
    """
    sweep_dir = tmp_path / host / sid
    sweep_dir.mkdir(parents=True)

    manifest = {
        "sweep_id": sid,
        "modem": "mediatek",
        "profile": "quick",
        "filters": [FILT],
        "offset_range": [0, 255],
        "offsets_per_filter": len(tested_offsets),
        "offset_strategy": "near_known",
        "values": VALUES,
        "total_combinations": len(tested_offsets) * len(VALUES),
        "exploit_timeout": 60,
        "start_time": "2026-04-16T12:53:45",
        "results_path": str(sweep_dir / "results.jsonl"),
        "progress_path": str(sweep_dir / "progress.jsonl"),
    }
    (sweep_dir / "manifest.json").write_text(json.dumps(manifest))

    with open(sweep_dir / "results.jsonl", "w") as f:
        for i, off in enumerate(tested_offsets):
            for val in VALUES:
                f.write(
                    json.dumps(
                        {
                            "sweep_id": sid,
                            "test_num": i,
                            "filter": FILT,
                            "offset": off,
                            "value": val,
                            "crash": off in crash_offsets,
                            "crash_id": "X" if off in crash_offsets else None,
                            "compile_success": off not in fail_offsets,
                            "execution_time_seconds": 1.0,
                        }
                    )
                    + "\n"
                )

    with open(sweep_dir / "progress.jsonl", "w") as f:
        f.write(
            json.dumps(
                {
                    "sweep_id": sid,
                    "tests_completed": len(tested_offsets) * len(VALUES),
                    "tests_total": len(tested_offsets) * len(VALUES),
                    "status": "completed",
                }
            )
            + "\n"
        )

    return sweep_dir


@pytest.fixture
def sweep_root(tmp_path, monkeypatch):
    """Redirect SWEEP_LOG_ROOT to a tmp dir for isolated sweep tests.

    Tests write under tmp_path/<host>/<sweep_id>/ to exercise the
    host-namespaced layout the streaming sync produces.
    """
    monkeypatch.setattr(data_loader, "SWEEP_LOG_ROOT", str(tmp_path))
    return tmp_path


def _stub_plan(offsets):
    """Build a stub generate_test_plan that returns a fixed offset set."""

    def stub(cfg):
        return [(FILT, o, v) for o in offsets for v in cfg.values]

    return stub


class TestHeatmapOffsetSelection:
    def test_uses_actual_offsets_when_plan_drifts(self, sweep_root, monkeypatch):
        """Planned offsets disjoint from tested → fall back to tested."""
        tested = [0, 1, 2, 58, 59, 60]
        _write_sweep(sweep_root, "drift001", tested, crash_offsets={60})
        monkeypatch.setattr(
            plan_module, "generate_test_plan", _stub_plan([100, 101, 102])
        )

        d = data_loader.load_sweep_data("drift001")
        h = d["heatmap"][FILT]

        assert h["offsets"] == sorted(tested)
        non_null = sum(1 for row in h["grid"] for c in row if c is not None)
        assert non_null == len(tested) * len(VALUES)
        # crash=True cells for offset 60 → 1 per value
        assert sum(1 for row in h["grid"] for c in row if c == 1) == len(VALUES)

    def test_unions_planned_and_tested_when_plan_matches(self, sweep_root, monkeypatch):
        """Plan overlaps with tested → grid offsets = planned ∪ tested."""
        tested = [10, 11, 12]
        planned = [10, 11, 12, 20, 21]  # overlaps tested, adds untested rows
        _write_sweep(sweep_root, "match001", tested)
        monkeypatch.setattr(plan_module, "generate_test_plan", _stub_plan(planned))

        d = data_loader.load_sweep_data("match001")
        h = d["heatmap"][FILT]

        assert h["offsets"] == sorted(set(planned) | set(tested))
        # Untested offsets 20, 21 should be fully null rows
        idx_20 = h["offsets"].index(20)
        idx_21 = h["offsets"].index(21)
        assert all(c is None for c in h["grid"][idx_20])
        assert all(c is None for c in h["grid"][idx_21])
        # Tested offsets have no nulls
        idx_10 = h["offsets"].index(10)
        assert all(c == 0 for c in h["grid"][idx_10])

    def test_falls_back_when_plan_import_fails(self, sweep_root, monkeypatch):
        """generate_test_plan raising → grid uses actual tested offsets."""
        tested = [7, 8, 9]
        _write_sweep(sweep_root, "fail001", tested)

        def boom(cfg):
            raise ImportError("synthetic: plan module unavailable")

        monkeypatch.setattr(plan_module, "generate_test_plan", boom)

        d = data_loader.load_sweep_data("fail001")
        h = d["heatmap"][FILT]

        assert h["offsets"] == sorted(tested)
        non_null = sum(1 for row in h["grid"] for c in row if c is not None)
        assert non_null == len(tested) * len(VALUES)

    def test_compile_fail_cells_marked_minus_one(self, sweep_root, monkeypatch):
        tested = [5]
        _write_sweep(sweep_root, "fail002", tested, fail_offsets={5})
        monkeypatch.setattr(plan_module, "generate_test_plan", _stub_plan([5]))

        d = data_loader.load_sweep_data("fail002")
        h = d["heatmap"][FILT]
        assert all(c == -1 for c in h["grid"][0])


def _completed_sweeps_on_disk():
    """Enumerate completed sweeps in real sweep_logs/ for regression coverage.

    Walks both the host-namespaced layout (`sweep_logs/<host>/<id>/`) and the
    legacy flat layout (`sweep_logs/<id>/`) so the regression suite keeps
    working through the migration.
    """
    sweep_root = os.path.join(AGENT_DIR, "sweep_logs")
    patterns = [
        os.path.join(sweep_root, "*", "*", "manifest.json"),  # host-namespaced
        os.path.join(sweep_root, "*", "manifest.json"),  # legacy flat
    ]
    ids: list[str] = []
    seen: set[str] = set()
    for pat in patterns:
        for mf in glob.glob(pat):
            sid = os.path.basename(os.path.dirname(mf))
            if sid in seen:
                continue
            prog = os.path.join(os.path.dirname(mf), "progress.jsonl")
            if not os.path.exists(prog):
                continue
            with open(prog, "r", encoding="utf-8") as f:
                lines = [ln for ln in f.read().splitlines() if ln.strip()]
            if not lines:
                continue
            try:
                last = json.loads(lines[-1])
            except json.JSONDecodeError:
                continue
            if last.get("status") == "completed":
                seen.add(sid)
                ids.append(sid)
    return ids


@pytest.mark.parametrize("sweep_id", _completed_sweeps_on_disk())
def test_heatmap_covers_all_results_for_completed_sweep(sweep_id):
    """For every completed sweep on disk, grid non-null cells == tests_completed.

    Regression guard: the original bug silently left 0a27da44's grid empty
    despite 525 completed tests. This asserts the invariant across all
    completed sweeps so future drift in plan replay can't recreate the gap.
    """
    d = data_loader.load_sweep_data(sweep_id)
    assert d is not None, f"load_sweep_data returned None for {sweep_id}"

    tests_completed = d["progress"]["tests_completed"]
    total_non_null = sum(
        1
        for h in d["heatmap"].values()
        for row in h["grid"]
        for c in row
        if c is not None
    )
    assert total_non_null == tests_completed, (
        f"Sweep {sweep_id}: {total_non_null} non-null grid cells "
        f"but {tests_completed} tests completed"
    )
