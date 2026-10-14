"""Retrieval Pipeline Eval — Tier 1, offline (STUB).

Exercises the research/retrieval pipeline (raw-GitHub extraction, blob
parsing, max_chars sensitivity, exploit-template correctness, GitHub URL/API
conversion, and directory navigation) against cached HTTP fixtures for
deterministic, no-network testing.

NOTE: This is a stub. 
"""

import json
import os
import sys

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(EVAL_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

FIXTURES_DIR = os.path.join(EVAL_DIR, "fixtures")
GROUND_TRUTH_PATH = os.path.join(EVAL_DIR, "ground_truth.json")


def load_ground_truth() -> list[dict]:
    """Load ground truth entries. The shipped stub has none."""
    with open(GROUND_TRUTH_PATH) as f:
        return json.load(f).get("entries", [])


def run_all(verbose: bool = True) -> dict:
    """Run all retrieval evals and return summary (stub).

    Returns the same result shape as the full eval (keyed by test name) so
    callers like `run_evals.py offline` work unchanged. With fixtures removed,
    every test list is empty.
    """
    if verbose:
        print("=" * 60)
        print("Retrieval Pipeline Eval — STUB (fixtures removed)")
        print("=" * 60)
        print("  Cached HTTP fixtures and ground truth removed from this")
        print("  public submission; no cases to run.")

    return {
        "raw_github": [],
        "github_blob": [],
        "max_chars_sensitivity": [],
        "exploit_template": [],
        "url_conversion": [],
        "directory_navigation": [],
    }


if __name__ == "__main__":
    run_all(verbose=True)
