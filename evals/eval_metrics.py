"""Tier 1 — Offline session metrics evals.

Parses tests.jsonl from a completed run and checks for
compile failures, novel crash discovery, and mutation value diversity.
"""

import json
import os
import re
import sys

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(EVAL_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)


def _load_tests(tests_jsonl_path: str) -> list[dict]:
    """Load test records from a tests.jsonl file."""
    tests = []
    with open(tests_jsonl_path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    tests.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return tests


def _known_exploit_names(known_crashes_path: str | None = None) -> set[str]:
    """Return the set of known/confirmed exploit names from known_crashes.json."""
    if known_crashes_path is None:
        from constants import KNOWN_CRASHES

        known_crashes_path = KNOWN_CRASHES
    try:
        with open(known_crashes_path) as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return set()
    return {c["name"] for c in data.get("confirmed_crashes", [])}


def _extract_mutation_values(exploit_code: str) -> list[str]:
    """Extract hex values assigned to pkt_buf from exploit source code.

    Returns list of lowercase hex strings like ['0xff', '0x67'].
    """
    pattern = r"pkt_buf\[[^\]]+\]\s*=\s*(0x[0-9a-fA-F]+)"
    return [m.lower() for m in re.findall(pattern, exploit_code)]


def _is_novel_test(test: dict, known_names: set[str]) -> bool:
    """Return True if this test is a novel attempt (not a known exploit reproduction)."""
    return test.get("exploit_name", "") not in known_names


# ── Test functions ──


def test_compile_failure_rate(tests_jsonl_path: str) -> dict:
    """Check compile failure rate across all tests in a run.

    A high compile failure rate means the agent is generating uncompilable
    code — either the prompt template is wrong or the agent is deviating
    from it.
    """
    tests = _load_tests(tests_jsonl_path)
    if not tests:
        return {"status": "skip", "reason": "no tests found"}

    total = len(tests)
    compile_failures = [t for t in tests if not t.get("compile_success", True)]
    failure_rate = len(compile_failures) / total

    failed_details = []
    for t in compile_failures:
        detail = {
            "test_id": t.get("test_id"),
            "exploit_name": t.get("exploit_name"),
        }
        # Check for common compile issues in the exploit code
        code = t.get("exploit_code", "")
        if '#include "ModulesInclude.hpp"' in code:
            detail["likely_cause"] = "quotes_include"
        elif "#include <ModulesInclude.hpp>" not in code:
            detail["likely_cause"] = "missing_include"
        else:
            detail["likely_cause"] = "other"
        failed_details.append(detail)

    return {
        "status": "pass" if failure_rate <= 0.1 else "fail",
        "total_tests": total,
        "compile_failures": len(compile_failures),
        "failure_rate": round(failure_rate, 3),
        "threshold": 0.1,
        "failed_tests": failed_details,
    }


def test_novel_crash_discovery_rate(
    tests_jsonl_path: str, known_crashes_path: str | None = None
) -> dict:
    """Check whether the agent discovered any novel crashes (not just reproductions).

    A novel crash is one where the exploit_name is NOT in the known_crashes.json
    list and crash == True.  Also breaks down crashes by category
    (publicly_known_crash, non_publicly_known_crash, fully_novel_crash).
    """
    tests = _load_tests(tests_jsonl_path)
    if not tests:
        return {"status": "skip", "reason": "no tests found"}

    known_names = _known_exploit_names(known_crashes_path)

    novel_tests = [t for t in tests if _is_novel_test(t, known_names)]
    novel_crashes = [t for t in novel_tests if t.get("crash")]
    repro_tests = [t for t in tests if not _is_novel_test(t, known_names)]
    repro_crashes = [t for t in repro_tests if t.get("crash")]

    novel_crash_rate = len(novel_crashes) / len(novel_tests) if novel_tests else 0.0

    # Three-way crash category breakdown across all crashes
    all_crashes = [t for t in tests if t.get("crash")]
    publicly_known = [
        t for t in all_crashes if t.get("crash_category") == "publicly_known_crash"
    ]
    non_publicly_known = [
        t for t in all_crashes if t.get("crash_category") == "non_publicly_known_crash"
    ]
    fully_novel = [
        t for t in all_crashes if t.get("crash_category") == "fully_novel_crash"
    ]

    return {
        "status": "pass" if len(novel_crashes) > 0 else "fail",
        "total_tests": len(tests),
        "reproductions": {
            "attempted": len(repro_tests),
            "crashed": len(repro_crashes),
        },
        "novel": {
            "attempted": len(novel_tests),
            "crashed": len(novel_crashes),
            "crash_rate": round(novel_crash_rate, 3),
            "names": [t.get("exploit_name") for t in novel_crashes],
        },
        "crash_categories": {
            "total_crashes": len(all_crashes),
            "publicly_known_crashes": len(publicly_known),
            "non_publicly_known_crashes": len(non_publicly_known),
            "fully_novel_crashes": len(fully_novel),
        },
    }


def test_mutation_value_diversity(
    tests_jsonl_path: str, known_crashes_path: str | None = None
) -> dict:
    """Check whether novel exploit attempts use diverse mutation values.

    The known crash patterns show that precise "valid-but-wrong" values
    (0x67, 0x5b, 0xa1, 0xd0) are effective, while naive values (0xFF,
    0x00) tend not to crash the modem. If >50% of novel mutation values
    are 0xff or 0x00, the agent isn't learning from the crash knowledge.
    """
    tests = _load_tests(tests_jsonl_path)
    if not tests:
        return {"status": "skip", "reason": "no tests found"}

    known_names = _known_exploit_names(known_crashes_path)
    naive_values = {"0xff", "0x00"}

    novel_tests = [t for t in tests if _is_novel_test(t, known_names)]
    # Only consider tests that compiled (have meaningful exploit code)
    novel_compiled = [t for t in novel_tests if t.get("compile_success", True)]

    if not novel_compiled:
        return {"status": "skip", "reason": "no compiled novel tests"}

    all_values = []
    per_test = []
    for t in novel_compiled:
        code = t.get("exploit_code", "")
        values = _extract_mutation_values(code)
        naive_count = sum(1 for v in values if v in naive_values)
        total = len(values)
        naive_frac = naive_count / total if total > 0 else 0.0
        per_test.append(
            {
                "exploit_name": t.get("exploit_name"),
                "values": values,
                "naive_count": naive_count,
                "naive_fraction": round(naive_frac, 2),
            }
        )
        all_values.extend(values)

    total_values = len(all_values)
    total_naive = sum(1 for v in all_values if v in naive_values)
    naive_rate = total_naive / total_values if total_values > 0 else 0.0

    return {
        "status": "pass" if naive_rate <= 0.5 else "fail",
        "total_novel_values": total_values,
        "naive_values_count": total_naive,
        "naive_rate": round(naive_rate, 3),
        "threshold": 0.5,
        "per_test": per_test,
    }


def run_by_run_id(run_id: str, verbose: bool = True) -> dict:
    """Run session metrics evals for a run identified by run_id.

    Reads modem from the run's manifest to load the correct known_crashes.json.
    """
    from evals.resolve_run import resolve_run

    info = resolve_run(run_id)
    kb_dir = info.get("kb_dir", "")
    tests_path = os.path.join(kb_dir, "tests.jsonl") if kb_dir else None
    if not tests_path or not os.path.exists(tests_path):
        return {"error": f"No tests.jsonl found for run_id {run_id}"}

    # Load known_crashes_path from manifest's device profile.
    # Supports both new-style ("device" + "protocol") and legacy ("modem") manifests.
    known_crashes_path = None
    device = info.get("device") or info.get("modem")
    protocol = info.get("protocol") or "fiveg"
    if device:
        try:
            from device_profile import load_device_profile

            profile = load_device_profile(device, protocol)
            known_crashes_path = profile.known_crashes_path
        except Exception:
            pass  # Fall back to constants default

    return run_all(tests_path, verbose=verbose, known_crashes_path=known_crashes_path)


def run_all(
    tests_jsonl_path: str, verbose: bool = True, known_crashes_path: str | None = None
) -> dict:
    """Run all session metrics evals against a tests.jsonl file."""
    results = {}

    if verbose:
        print("=" * 60)
        print("Session Metrics Eval")
        print(f"  source: {tests_jsonl_path}")
        print("=" * 60)

    # 1. Compile failure rate
    if verbose:
        print("\n--- test_compile_failure_rate ---")
    cfr = test_compile_failure_rate(tests_jsonl_path)
    results["compile_failure_rate"] = cfr
    if verbose:
        if cfr.get("status") == "skip":
            print(f"  SKIP: {cfr['reason']}")
        else:
            print(
                f"  {cfr['status'].upper()}: {cfr['compile_failures']}/{cfr['total_tests']} "
                f"failed ({cfr['failure_rate']:.1%}), threshold ≤{cfr['threshold']:.0%}"
            )
            for ft in cfr.get("failed_tests", []):
                print(
                    f"    {ft['test_id']} ({ft['exploit_name']}): {ft['likely_cause']}"
                )

    # 2. Novel crash discovery
    if verbose:
        print("\n--- test_novel_crash_discovery_rate ---")
    ncr = test_novel_crash_discovery_rate(
        tests_jsonl_path, known_crashes_path=known_crashes_path
    )
    results["novel_crash_discovery"] = ncr
    if verbose:
        if ncr.get("status") == "skip":
            print(f"  SKIP: {ncr['reason']}")
        else:
            novel = ncr["novel"]
            repro = ncr["reproductions"]
            print(
                f"  {ncr['status'].upper()}: {novel['crashed']}/{novel['attempted']} "
                f"novel attempts crashed, {repro['crashed']}/{repro['attempted']} reproductions crashed"
            )
            if novel["names"]:
                print(f"    novel crashes: {novel['names']}")

    # 3. Mutation value diversity
    if verbose:
        print("\n--- test_mutation_value_diversity ---")
    mvd = test_mutation_value_diversity(
        tests_jsonl_path, known_crashes_path=known_crashes_path
    )
    results["mutation_value_diversity"] = mvd
    if verbose:
        if mvd.get("status") == "skip":
            print(f"  SKIP: {mvd['reason']}")
        else:
            print(
                f"  {mvd['status'].upper()}: {mvd['naive_values_count']}/{mvd['total_novel_values']} "
                f"naive values ({mvd['naive_rate']:.0%}), threshold ≤{mvd['threshold']:.0%}"
            )
            for pt in mvd.get("per_test", []):
                print(
                    f"    {pt['exploit_name']}: {pt['values']} "
                    f"(naive: {pt['naive_count']}/{len(pt['values'])})"
                )

    return results


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python evals/eval_metrics.py <tests.jsonl>")
        sys.exit(1)
    run_all(sys.argv[1], verbose=True)
