"""Tool Effectiveness Analyzer — retroactive analysis of agent_metrics JSONL.

Key metrics:
- Research-to-test ratio: (web_search + fetch_url) / execute_test — target < 5:1 after turn 5
- First test turn: When the agent first called execute_test
- Wasted fetches: fetch_url calls that don't produce a save_finding within 2 turns
- Research yield: (findings tagged web_sourced) / (web_search + fetch_url calls)
"""

import glob
import json
import os
import sys

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(EVAL_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

RESEARCH_TOOLS = {"web_search", "fetch_url", "query_papers", "read_paper"}
TEST_TOOLS = {"execute_test"}
SAVE_TOOLS = {"save_finding"}


def analyze_metrics_file(metrics_path: str) -> dict:
    """Analyze a single agent_metrics_*.jsonl file."""
    records = []
    with open(metrics_path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass

    if not records:
        return {"error": "empty metrics file", "path": metrics_path}

    total_turns = len(records)

    # Count tool calls
    research_calls = 0
    test_calls = 0
    save_calls = 0
    fetch_url_calls = 0
    web_search_calls = 0

    first_test_turn = None
    first_crash_turn = None

    # Track fetch_url turns for waste analysis
    fetch_turns = []
    save_turns = []

    for rec in records:
        turn = rec["turn"]
        tool_counts = rec.get("tool_counts", {})

        for tool, count in tool_counts.items():
            if tool in RESEARCH_TOOLS:
                research_calls += count
            if tool in TEST_TOOLS:
                test_calls += count
                if first_test_turn is None:
                    first_test_turn = turn
            if tool in SAVE_TOOLS:
                save_calls += count
                save_turns.append(turn)
            if tool == "fetch_url":
                fetch_url_calls += count
                fetch_turns.append(turn)
            if tool == "web_search":
                web_search_calls += count

        if rec.get("turn_crashes", 0) > 0 and first_crash_turn is None:
            first_crash_turn = turn

    # Research-to-test ratio
    if test_calls > 0:
        research_test_ratio = round(research_calls / test_calls, 2)
    else:
        research_test_ratio = float("inf")

    # Research-to-test ratio after turn 5
    research_after_5 = 0
    test_after_5 = 0
    for rec in records:
        if rec["turn"] <= 5:
            continue
        tc = rec.get("tool_counts", {})
        for tool, count in tc.items():
            if tool in RESEARCH_TOOLS:
                research_after_5 += count
            if tool in TEST_TOOLS:
                test_after_5 += count

    if test_after_5 > 0:
        research_test_ratio_after_5 = round(research_after_5 / test_after_5, 2)
    else:
        research_test_ratio_after_5 = float("inf") if research_after_5 > 0 else 0.0

    # Wasted fetches: fetch_url not followed by save_finding within 2 turns
    wasted_fetches = 0
    for ft in fetch_turns:
        has_save = any(st >= ft and st <= ft + 2 for st in save_turns)
        if not has_save:
            wasted_fetches += 1

    wasted_fetch_rate = (
        round(wasted_fetches / fetch_url_calls, 2) if fetch_url_calls > 0 else 0.0
    )

    # Token usage
    total_input_tokens = records[-1].get("cumulative_input_tokens", 0)
    total_output_tokens = records[-1].get("cumulative_output_tokens", 0)
    total_crashes = records[-1].get("cumulative_crashes", 0)
    unique_crashes = records[-1].get("cumulative_unique_crashes", 0)

    # Phase breakdown: turns before first test = research phase
    research_turns = first_test_turn - 1 if first_test_turn else total_turns
    testing_turns = total_turns - research_turns

    return {
        "path": metrics_path,
        "total_turns": total_turns,
        "research_calls": research_calls,
        "test_calls": test_calls,
        "save_calls": save_calls,
        "fetch_url_calls": fetch_url_calls,
        "web_search_calls": web_search_calls,
        "first_test_turn": first_test_turn,
        "first_crash_turn": first_crash_turn,
        "research_test_ratio": research_test_ratio,
        "research_test_ratio_after_5": research_test_ratio_after_5,
        "wasted_fetches": wasted_fetches,
        "wasted_fetch_rate": wasted_fetch_rate,
        "research_turns": research_turns,
        "testing_turns": testing_turns,
        "total_input_tokens": total_input_tokens,
        "total_output_tokens": total_output_tokens,
        "total_crashes": total_crashes,
        "unique_crashes": unique_crashes,
    }


def analyze_by_run_id(run_id: str) -> dict:
    """Analyze tool effectiveness for a single run identified by run_id."""
    from evals.resolve_run import resolve_run

    info = resolve_run(run_id)
    metrics_path = info.get("metrics")
    if metrics_path and os.path.exists(metrics_path):
        return analyze_metrics_file(metrics_path)
    return {"error": f"No metrics file for run_id {run_id}"}


def analyze_all_runs(verbose: bool = True) -> list[dict]:
    """Analyze all agent_metrics_*.jsonl files across every host subdir under
    runtime_logs/ (plus the legacy flat layout)."""
    from constants import RUNTIME_LOG_ROOT

    files = sorted(
        set(
            glob.glob(os.path.join(RUNTIME_LOG_ROOT, "*", "agent_metrics_*.jsonl"))
            + glob.glob(os.path.join(RUNTIME_LOG_ROOT, "agent_metrics_*.jsonl"))
        )
    )

    if verbose:
        print("=" * 60)
        print("Tool Effectiveness Analysis")
        print("=" * 60)
        print(f"Found {len(files)} metrics files\n")

    results = []
    for f in files:
        result = analyze_metrics_file(f)
        results.append(result)

        if verbose:
            run_id = (
                os.path.basename(f).replace("agent_metrics_", "").replace(".jsonl", "")
            )
            first_test = result.get("first_test_turn", "never")
            ratio = result.get("research_test_ratio", "N/A")
            crashes = result.get("total_crashes", 0)
            unique = result.get("unique_crashes", 0)
            turns = result.get("total_turns", 0)
            wasted = result.get("wasted_fetch_rate", 0)
            print(
                f"  {run_id}: turns={turns} first_test=T{first_test} "
                f"R:T={ratio} crashes={crashes}/{unique}u wasted_fetch={wasted:.0%}"
            )

    if verbose and results:
        # Summary stats
        print(f"\n--- Summary across {len(results)} runs ---")
        first_tests = [
            r["first_test_turn"] for r in results if r.get("first_test_turn")
        ]
        if first_tests:
            avg_first_test = sum(first_tests) / len(first_tests)
            print(f"  Avg first test turn: {avg_first_test:.1f}")
            print(
                f"  Runs where first_test > 10: {sum(1 for t in first_tests if t > 10)}/{len(first_tests)}"
            )

        crashing_runs = sum(1 for r in results if r.get("total_crashes", 0) > 0)
        print(f"  Runs with crashes: {crashing_runs}/{len(results)}")

        ratios = [
            r["research_test_ratio"]
            for r in results
            if r.get("research_test_ratio") != float("inf")
        ]
        if ratios:
            print(f"  Avg research:test ratio: {sum(ratios) / len(ratios):.1f}")

    return results


def run_all(verbose: bool = True) -> list[dict]:
    return analyze_all_runs(verbose=verbose)


if __name__ == "__main__":
    analyze_all_runs(verbose=True)
