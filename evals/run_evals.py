#!/usr/bin/env python3
"""CLI entry point for the evals infrastructure.

Usage:
    # Run ALL evals for a specific run
    python evals/run_evals.py run <run_id>

    # Individual evals by run_id
    python evals/run_evals.py score-run <run_id>
    python evals/run_evals.py bottleneck <run_id>
    python evals/run_evals.py session-metrics <run_id>
    python evals/run_evals.py analyze-run <run_id>

    # Batch commands (no run_id — iterate all)
    python evals/run_evals.py analyze-all
    python evals/run_evals.py score-all
    python evals/run_evals.py list-runs

    # Offline fixture-based evals
    python evals/run_evals.py offline
"""

import argparse
import json
import os
import sys

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(EVAL_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)


def cmd_offline(args):
    """Run all offline (Tier 1) evals."""
    from evals.eval_retrieval import run_all as run_retrieval

    results = run_retrieval(verbose=True)

    passed = sum(1 for r in results.get("raw_github", []) if r.get("status") == "pass")
    total = len(results.get("raw_github", []))
    skipped = sum(1 for r in results.get("raw_github", []) if r.get("status") == "skip")

    print(f"\n{'=' * 60}")
    print(f"Offline Eval Summary: {passed}/{total} passed, {skipped} skipped")
    print(f"{'=' * 60}")


def cmd_score_run(args):
    """Score a specific run's findings by run_id."""
    from evals.eval_research_quality import score_by_run_id

    result = score_by_run_id(args.run_id, verbose=True)
    if result.get("error"):
        print(f"Error: {result['error']}")
        sys.exit(1)


def cmd_score_all(args):
    """Score all sessions."""
    from evals.eval_research_quality import run_all as run_quality

    device = getattr(args, "device", None)
    run_quality(verbose=True, device=device)


def cmd_bottleneck(args):
    """Classify bottleneck for a run by run_id."""
    from evals.eval_bottleneck import classify_by_run_id

    result = classify_by_run_id(args.run_id, verbose=True)
    if getattr(args, "json", False):
        print(json.dumps(result, indent=2, default=str))


def cmd_session_metrics(args):
    """Run session metrics evals for a run by run_id."""
    from evals.eval_metrics import run_by_run_id

    result = run_by_run_id(args.run_id, verbose=True)
    if result.get("error"):
        print(f"Error: {result['error']}")
        sys.exit(1)
    if isinstance(result, dict) and "error" not in result:
        statuses = [v.get("status") for v in result.values()]
        passed = statuses.count("pass")
        failed = statuses.count("fail")
        skipped = statuses.count("skip")
        print(
            f"\nSession Metrics Summary: {passed} passed, {failed} failed, {skipped} skipped"
        )


def cmd_analyze_run(args):
    """Run tool effectiveness analysis for a single run by run_id."""
    from evals.eval_tool_effectiveness import analyze_by_run_id

    result = analyze_by_run_id(args.run_id)
    if result.get("error"):
        print(f"Error: {result['error']}")
        sys.exit(1)
    # Print summary
    print("=" * 60)
    print(f"Tool Effectiveness: {args.run_id}")
    print("=" * 60)
    print(
        f"  Turns: {result.get('total_turns')} | First test: T{result.get('first_test_turn')} | "
        f"Tests: {result.get('test_calls')} | Crashes: {result.get('total_crashes')}"
    )
    print(
        f"  R:T ratio: {result.get('research_test_ratio')} | "
        f"Wasted fetches: {result.get('wasted_fetch_rate', 0):.0%}"
    )


def cmd_analyze_all(args):
    """Run retroactive tool effectiveness analysis."""
    from evals.eval_tool_effectiveness import run_all as run_effectiveness

    run_effectiveness(verbose=True)


def cmd_run_all_for_id(args):
    """Run ALL evals for a specific run_id."""
    run_id = args.run_id

    print("\n" + "=" * 70)
    print(f"ALL EVALS FOR RUN: {run_id}")
    print("=" * 70)

    print("\n--- Research Quality ---")
    from evals.eval_research_quality import score_by_run_id

    score_by_run_id(run_id, verbose=True)

    print("\n--- Session Metrics ---")
    from evals.eval_metrics import run_by_run_id

    run_by_run_id(run_id, verbose=True)

    print("\n--- Tool Effectiveness ---")
    from evals.eval_tool_effectiveness import analyze_by_run_id

    result = analyze_by_run_id(run_id)
    if not result.get("error"):
        print(
            f"  Turns: {result.get('total_turns')} | First test: T{result.get('first_test_turn')} | "
            f"Tests: {result.get('test_calls')} | Crashes: {result.get('total_crashes')}"
        )
    else:
        print(f"  {result['error']}")

    print("\n--- Bottleneck Classification ---")
    from evals.eval_bottleneck import classify_by_run_id

    classify_by_run_id(run_id, verbose=True)


def cmd_list_runs(args):
    """List all known runs."""
    from evals.resolve_run import list_runs

    runs = list_runs()
    if not runs:
        print("No runs found (no manifest files in runtime_logs/).")
        return
    print(f"{'=' * 60}")
    print(f"Known Runs ({len(runs)})")
    print(f"{'=' * 60}")
    for r in runs:
        print(
            f"  {r['run_id']}  ts={r.get('timestamp', '?')}  modem={r.get('modem', '?')}  session={r.get('session_id', '?')}"
        )


def cmd_all(args):
    """Run everything."""
    print("\n" + "=" * 70)
    print("PHASE 1: Offline Retrieval Evals")
    print("=" * 70)
    cmd_offline(args)

    print("\n" + "=" * 70)
    print("PHASE 2: Research Quality Scoring (all sessions)")
    print("=" * 70)
    cmd_score_all(args)

    print("\n" + "=" * 70)
    print("PHASE 3: Tool Effectiveness Analysis")
    print("=" * 70)
    cmd_analyze_all(args)


def main():
    parser = argparse.ArgumentParser(
        description="Agentic Fuzzer Evals Infrastructure",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    subparsers = parser.add_subparsers(dest="command")

    # Run ALL evals for a run_id
    sub = subparsers.add_parser("run", help="Run ALL evals for a run_id")
    sub.add_argument("run_id", help="Run ID")
    sub.set_defaults(func=cmd_run_all_for_id)

    # Score a run
    sub = subparsers.add_parser("score-run", help="Score a run's findings")
    sub.add_argument("run_id", help="Run ID")
    sub.set_defaults(func=cmd_score_run)

    # Score all
    sub = subparsers.add_parser("score-all", help="Score all sessions")
    sub.add_argument("--device", help="Target device filter")
    sub.set_defaults(func=cmd_score_all)

    # Bottleneck
    sub = subparsers.add_parser("bottleneck", help="Classify failure bottleneck")
    sub.add_argument("run_id", help="Run ID")
    sub.add_argument("--json", action="store_true", help="Output JSON")
    sub.set_defaults(func=cmd_bottleneck)

    # Session metrics
    sub = subparsers.add_parser("session-metrics", help="Run session metrics evals")
    sub.add_argument("run_id", help="Run ID")
    sub.set_defaults(func=cmd_session_metrics)

    # Analyze single run
    sub = subparsers.add_parser("analyze-run", help="Tool effectiveness for one run")
    sub.add_argument("run_id", help="Run ID")
    sub.set_defaults(func=cmd_analyze_run)

    # Analyze all
    sub = subparsers.add_parser(
        "analyze-all", help="Retroactive tool effectiveness analysis"
    )
    sub.set_defaults(func=cmd_analyze_all)

    # List runs
    sub = subparsers.add_parser("list-runs", help="List all known runs")
    sub.set_defaults(func=cmd_list_runs)

    # Offline evals
    sub = subparsers.add_parser("offline", help="Run offline (Tier 1) retrieval evals")
    sub.set_defaults(func=cmd_offline)

    # All
    sub = subparsers.add_parser("all", help="Run all evals")
    sub.set_defaults(func=cmd_all)

    args = parser.parse_args()

    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
