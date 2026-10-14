#!/usr/bin/env python3
"""Evaluation runner for RQ1 — runs N agent sessions and collects metrics into a CSV.

Usage:
    python rq_scripts/run_eval_rq1.py --runs 3 --max-turns 30 --version v1
    python rq_scripts/run_eval_rq1.py --runs 3 --max-turns 30 --version v2 --model anthropic/claude-sonnet-4.6
"""

import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
import uuid

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from constants import RUNTIME_LOG_PATH, REPORTS_PATH

REPORTS_DIR = REPORTS_PATH  # host-scoped: AGENT_DIR/reports/<host>/

CSV_COLUMNS = [
    "eval_id",
    "run_id",
    "session_id",
    "model",
    "version",
    "device",
    "protocol",
    "max_turns",
    "actual_turns",
    "rq_max_score",
    "rq_max_level",
    "rq_mean_score",
    "publicly_known_crashes",
    "non_publicly_known_crashes",
    "fully_novel_crashes",
    "total_crashes",
    "total_input_tokens",
    "total_output_tokens",
    "unique_crashes",
    "unique_novel",
    "total_tests",
    "time_to_first_crash_seconds",
    "tests_till_first_crash",
    "total_session_time_seconds",
]


# ── Helpers ──────────────────────────────────────────────────────────────────


def parse_run_id_from_output(output: str) -> str | None:
    """Extract run_id from subprocess output by matching 'Run ID: <hex8>'."""
    match = re.search(r"Run ID:\s*([0-9a-f]{8})\b", output)
    return match.group(1) if match else None


def find_new_manifest(before: set[str]) -> str | None:
    """Fallback: find a manifest file that appeared after `before` snapshot."""
    after = set(_list_manifest_files())
    new = after - before
    if len(new) == 1:
        return new.pop()
    # Multiple new manifests — pick the newest by mtime
    if new:
        return max(new, key=os.path.getmtime)
    return None


def _list_manifest_files() -> list[str]:
    """Enumerate manifests across every host subdir under RUNTIME_LOG_ROOT,
    plus the legacy flat layout."""
    import glob
    from constants import RUNTIME_LOG_ROOT

    matches = set(glob.glob(os.path.join(RUNTIME_LOG_ROOT, "*", "*_manifest.json")))
    matches.update(glob.glob(os.path.join(RUNTIME_LOG_ROOT, "*_manifest.json")))
    return sorted(matches)


def extract_run_id_from_manifest(manifest_path: str) -> str | None:
    """Read run_id from a manifest JSON file."""
    try:
        with open(manifest_path) as f:
            return json.load(f).get("run_id")
    except (json.JSONDecodeError, OSError):
        return None


def extract_metrics(run_id: str) -> dict:
    """Read the last record from agent_metrics JSONL to get cumulative stats."""
    import glob
    from constants import RUNTIME_LOG_ROOT

    # The metrics file may live under any host subdir or in the legacy flat layout.
    candidates = glob.glob(
        os.path.join(RUNTIME_LOG_ROOT, "*", f"agent_metrics_{run_id}.jsonl")
    ) + glob.glob(os.path.join(RUNTIME_LOG_ROOT, f"agent_metrics_{run_id}.jsonl"))
    metrics_path = (
        candidates[0]
        if candidates
        else os.path.join(RUNTIME_LOG_PATH, f"agent_metrics_{run_id}.jsonl")
    )
    return extract_metrics_from_file(metrics_path)


def extract_metrics_from_file(metrics_path: str) -> dict:
    """Read first + last records from a metrics JSONL file.

    First record gives a fallback session-start timestamp; last record carries
    cumulative state plus the first-crash markers stamped by agent_core.
    """
    defaults = {
        "actual_turns": 0,
        "cumulative_publicly_known": 0,
        "cumulative_non_publicly_known": 0,
        "cumulative_fully_novel": 0,
        "cumulative_crashes": 0,
        "cumulative_input_tokens": 0,
        "cumulative_output_tokens": 0,
        "unique_crashes": 0,
        "unique_novel": 0,
        "total_tests": 0,
        "time_to_first_crash_seconds": "N/A",
        "tests_till_first_crash": "N/A",
        "total_session_time_seconds": 0.0,
    }
    if not os.path.exists(metrics_path):
        return defaults

    first_line = None
    last_line = None
    try:
        with open(metrics_path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                if first_line is None:
                    first_line = line
                last_line = line
    except OSError:
        return defaults

    if not last_line:
        return defaults

    try:
        last = json.loads(last_line)
    except json.JSONDecodeError:
        return defaults

    try:
        first = json.loads(first_line) if first_line else last
    except json.JSONDecodeError:
        first = last

    session_start = last.get("session_start_time") or first.get("timestamp")
    last_ts = last.get("timestamp")
    total_session_time = 0.0
    if session_start and last_ts:
        total_session_time = round(max(0.0, last_ts - session_start), 2)

    first_crash_ts = last.get("first_crash_timestamp")
    if first_crash_ts and session_start:
        time_to_first_crash = round(max(0.0, first_crash_ts - session_start), 2)
        tests_till_first_crash = last.get("first_crash_test_count", "N/A")
        if tests_till_first_crash is None:
            tests_till_first_crash = "N/A"
    else:
        time_to_first_crash = "N/A"
        tests_till_first_crash = "N/A"

    return {
        "actual_turns": last.get("turn", 0),
        "cumulative_publicly_known": last.get("cumulative_publicly_known", 0),
        "cumulative_non_publicly_known": last.get("cumulative_non_publicly_known", 0),
        "cumulative_fully_novel": last.get("cumulative_fully_novel", 0),
        "cumulative_crashes": last.get("cumulative_crashes", 0),
        "cumulative_input_tokens": last.get("cumulative_input_tokens", 0),
        "cumulative_output_tokens": last.get("cumulative_output_tokens", 0),
        "unique_crashes": last.get("session_unique_crashes", 0),
        "unique_novel": last.get("session_unique_novel_crashes", 0),
        "total_tests": last.get("cumulative_test_count", 0),
        "time_to_first_crash_seconds": time_to_first_crash,
        "tests_till_first_crash": tests_till_first_crash,
        "total_session_time_seconds": total_session_time,
    }


def score_research_quality(run_id: str) -> dict:
    """Score research quality for a completed run."""
    from evals.resolve_run import resolve_run
    from evals.eval_research_quality import score_session

    info = resolve_run(run_id)
    kb_dir = info.get("kb_dir")
    if not kb_dir or not os.path.isdir(kb_dir):
        return {"max_score": 0, "max_level": "L0", "mean_score": 0.0}

    result = score_session(kb_dir, device=info.get("device"))
    return {
        "max_score": result.get("max_score", 0),
        "max_level": result.get("max_level", "L0"),
        "mean_score": result.get("mean_score", 0.0),
    }


def build_csv_row(
    run_id: str | None,
    session_id: str | None,
    model: str,
    version: str,
    max_turns: int,
    metrics: dict,
    rq_scores: dict,
    device: str = "mediatek",
    protocol: str = "fiveg",
    eval_id: str = "",
) -> dict:
    """Build a single CSV row dict from collected data."""
    return {
        "eval_id": eval_id,
        "run_id": run_id or "N/A",
        "session_id": session_id or "N/A",
        "model": model,
        "version": version,
        "device": device,
        "protocol": protocol,
        "max_turns": max_turns,
        "actual_turns": metrics.get("actual_turns", 0),
        "rq_max_score": rq_scores.get("max_score", 0),
        "rq_max_level": rq_scores.get("max_level", "L0"),
        "rq_mean_score": rq_scores.get("mean_score", 0.0),
        "publicly_known_crashes": metrics.get("cumulative_publicly_known", 0),
        "non_publicly_known_crashes": metrics.get("cumulative_non_publicly_known", 0),
        "fully_novel_crashes": metrics.get("cumulative_fully_novel", 0),
        "total_crashes": metrics.get("cumulative_crashes", 0),
        "total_input_tokens": metrics.get("cumulative_input_tokens", 0),
        "total_output_tokens": metrics.get("cumulative_output_tokens", 0),
        "unique_crashes": metrics.get("unique_crashes", 0),
        "unique_novel": metrics.get("unique_novel", 0),
        "total_tests": metrics.get("total_tests", 0),
        "time_to_first_crash_seconds": metrics.get(
            "time_to_first_crash_seconds", "N/A"
        ),
        "tests_till_first_crash": metrics.get("tests_till_first_crash", "N/A"),
        "total_session_time_seconds": metrics.get("total_session_time_seconds", 0.0),
    }


def write_csv(rows: list[dict], output_path: str) -> None:
    """Write rows to a CSV file."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_COLUMNS)
        writer.writeheader()
        writer.writerows(rows)

    # Mirror each CSV row to the Postgres ingest API. Idempotent on
    # run_id (server-side ON CONFLICT (run_id) DO UPDATE) — use the CSV
    # file's mtime as evaluated_at so re-ingesting the same row across
    # incremental rewrites doesn't churn the timestamp.
    try:
        evaluated_at = os.path.getmtime(output_path)
    except OSError:
        evaluated_at = time.time()

    def _none_if_na(v):
        return None if v == "N/A" else v

    for row in rows:
        run_id = row.get("run_id")
        if not run_id or run_id == "N/A":
            continue
        try:
            from ingest_client import enqueue

            payload = {
                "eval_id": row.get("eval_id") or None,
                "run_id": run_id,
                "version": row.get("version", ""),
                "evaluated_at": evaluated_at,
                "session_id": row.get("session_id"),
                "model": row.get("model"),
                "device": row.get("device"),
                "protocol": row.get("protocol"),
                "max_turns": row.get("max_turns"),
                "actual_turns": row.get("actual_turns"),
                "rq_max_score": row.get("rq_max_score"),
                "rq_max_level": row.get("rq_max_level"),
                "rq_mean_score": row.get("rq_mean_score"),
                "publicly_known_crashes": row.get("publicly_known_crashes"),
                "non_publicly_known_crashes": row.get("non_publicly_known_crashes"),
                "fully_novel_crashes": row.get("fully_novel_crashes"),
                "total_crashes": row.get("total_crashes"),
                "total_input_tokens": row.get("total_input_tokens"),
                "total_output_tokens": row.get("total_output_tokens"),
                "unique_crashes": row.get("unique_crashes"),
                "unique_novel": row.get("unique_novel"),
                "total_tests": row.get("total_tests"),
                "time_to_first_crash_seconds": _none_if_na(
                    row.get("time_to_first_crash_seconds")
                ),
                "tests_till_first_crash": _none_if_na(
                    row.get("tests_till_first_crash")
                ),
                "total_session_time_seconds": row.get("total_session_time_seconds"),
                "source_csv_path": output_path,
            }
            enqueue("evaluation", payload, run_id=run_id)
        except Exception:
            # Eval CSV is the durable record; ingest is best-effort here.
            pass


def print_summary(rows: list[dict]) -> None:
    """Print a summary table to stdout."""
    if not rows:
        print("No results to display.")
        return

    # Column widths
    widths = {
        col: max(len(col), max(len(str(r[col])) for r in rows)) for col in CSV_COLUMNS
    }
    header = " | ".join(col.ljust(widths[col]) for col in CSV_COLUMNS)
    separator = "-+-".join("-" * widths[col] for col in CSV_COLUMNS)

    print()
    print("=" * len(header))
    print("Evaluation Results")
    print("=" * len(header))
    print(header)
    print(separator)
    for row in rows:
        print(" | ".join(str(row[col]).ljust(widths[col]) for col in CSV_COLUMNS))
    print()


# ── Main ─────────────────────────────────────────────────────────────────────


def run_single_agent(
    run_index: int,
    max_turns: int,
    model: str,
    version: str,
    device: str,
    protocol: str,
    cold_start: bool,
    hub_loc: str = None,
    hub_port: int = None,
    host_port: str = None,
    target_port: str = None,
) -> dict:
    """Run a single agent session and collect results."""
    print(f"\n{'=' * 60}")
    print(
        f"Run {run_index + 1}: version={version}, model={model}, device={device}, protocol={protocol}, max_turns={max_turns}"
    )
    print(f"{'=' * 60}")

    # Snapshot manifests before
    manifests_before = set(_list_manifest_files())

    # Build command
    cmd = [
        sys.executable,
        os.path.join(AGENT_DIR, "run_agent.py"),
        "--max-turns",
        str(max_turns),
        "--version",
        version,
        "--device",
        device,
        "--protocol",
        protocol,
    ]
    if model:
        cmd.extend(["--model", model])
    if cold_start:
        cmd.append("--cold-start")
    if hub_loc:
        cmd.extend(["--hub-loc", hub_loc])
    if hub_port is not None:
        cmd.extend(["--hub-port", str(hub_port)])
    if host_port:
        cmd.extend(["--host-port", host_port])
    if target_port:
        cmd.extend(["--target-port", target_port])

    # Build a temporary log path to capture subprocess output for run_id parsing.
    # The agent also writes its own structured logs to runtime_logs/.
    ts = time.strftime("%Y%m%d_%H%M%S")
    log_path = os.path.join(RUNTIME_LOG_PATH, f"eval_{run_index}_{version}_{ts}.log")

    print(f"  Log: {log_path}")
    print(f"  Command: {' '.join(cmd)}")

    run_id = None
    session_id = None

    try:
        with open(log_path, "w") as log_file:
            proc = subprocess.run(
                cmd,
                stdout=log_file,
                stderr=subprocess.STDOUT,
                timeout=None,  # agent manages its own turn limit
            )

        # Parse run_id from log output
        with open(log_path, errors="replace") as f:
            output = f.read()
        run_id = parse_run_id_from_output(output)

        # Fallback: diff manifests
        if not run_id:
            new_manifest = find_new_manifest(manifests_before)
            if new_manifest:
                run_id = extract_run_id_from_manifest(new_manifest)

        if run_id:
            print(f"  Run ID: {run_id}")

            # Get session_id from manifest
            from evals.resolve_run import resolve_run

            info = resolve_run(run_id)
            session_id = info.get("session_id")

            # Collect metrics
            metrics = extract_metrics(run_id)
            try:
                rq_scores = score_research_quality(run_id)
            except Exception as e:
                print(f"  WARNING: RQ scoring failed: {e}")
                rq_scores = {"max_score": 0, "max_level": "L0", "mean_score": 0.0}

            print(
                f"  Turns: {metrics['actual_turns']}, Crashes: {metrics['cumulative_crashes']}"
            )
            print(f"  RQ: {rq_scores['max_level']} (mean={rq_scores['mean_score']})")

            return {
                "run_id": run_id,
                "session_id": session_id,
                "metrics": metrics,
                "rq_scores": rq_scores,
                "exit_code": proc.returncode,
            }
        else:
            print("  WARNING: Could not determine run_id")
            return {
                "run_id": None,
                "session_id": None,
                "metrics": {},
                "rq_scores": {},
                "exit_code": proc.returncode,
            }

    except Exception as e:
        print(f"  ERROR: {e}")
        return {
            "run_id": run_id,
            "session_id": session_id,
            "metrics": {},
            "rq_scores": {},
            "exit_code": -1,
        }


def main():
    parser = argparse.ArgumentParser(
        description="Run N agent evaluations and collect metrics into a CSV report."
    )
    parser.add_argument(
        "--runs", type=int, default=3, help="Number of agent runs (default: 3)"
    )
    parser.add_argument(
        "--max-turns", type=int, default=30, help="Max turns per run (default: 30)"
    )
    parser.add_argument(
        "--model",
        type=str,
        default="anthropic/claude-sonnet-4.6",
        help="LLM model ID (default: anthropic/claude-sonnet-4.6)",
    )
    parser.add_argument(
        "--version",
        type=str,
        default="v1",
        choices=["v1", "v2", "v3", "v3f", "full"],
        help="Experiment version (default: v1)",
    )
    from device_profile import get_active_device

    _default_device, _default_protocol = get_active_device()
    parser.add_argument(
        "--protocol",
        type=str,
        required=True,
        choices=["fiveg", "bt", "wifi"],
        help="Protocol to fuzz (fiveg, bt, wifi)",
    )
    parser.add_argument(
        "--device",
        type=str,
        default=_default_device,
        help="Device profile ID (default: from data/active_device.json)",
    )
    parser.add_argument(
        "--cold-start", action="store_true", help="Pass --cold-start to agent"
    )
    parser.add_argument(
        "--hub-loc",
        type=str,
        default="1-3",
        help="USB hub location for uhubctl (default: 1-3)",
    )
    parser.add_argument(
        "--hub-port",
        type=int,
        default=1,
        help="USB hub port for uhubctl (default: 1)",
    )
    parser.add_argument(
        "--host-port",
        type=str,
        default="/dev/ttyUSB1",
        help="Host adapter serial port (Bluetooth ESP32, default: /dev/ttyUSB1)",
    )
    parser.add_argument(
        "--target-port",
        type=str,
        default="/dev/ttyUSB2",
        help="Target board serial port (Bluetooth ESP32, default: /dev/ttyUSB2)",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output CSV path (default: reports/<host>/eval_<version>_<timestamp>.csv)",
    )
    args = parser.parse_args()

    # Default output path
    if not args.output:
        os.makedirs(REPORTS_DIR, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S")
        args.output = os.path.join(REPORTS_DIR, f"eval_{args.version}_{ts}.csv")

    eval_id = uuid.uuid4().hex

    print(f"Evaluation: {args.runs} runs x {args.max_turns} turns")
    print(f"Model: {args.model} | Version: {args.version}")
    print(f"Eval ID: {eval_id}")
    print(f"Output: {args.output}")

    rows = []
    for i in range(args.runs):
        result = run_single_agent(
            run_index=i,
            max_turns=args.max_turns,
            model=args.model,
            version=args.version,
            device=args.device,
            protocol=args.protocol,
            cold_start=args.cold_start,
            hub_loc=args.hub_loc,
            hub_port=args.hub_port,
            host_port=args.host_port,
            target_port=args.target_port,
        )
        row = build_csv_row(
            run_id=result.get("run_id"),
            session_id=result.get("session_id"),
            model=args.model,
            version=args.version,
            max_turns=args.max_turns,
            metrics=result.get("metrics", {}),
            rq_scores=result.get("rq_scores", {}),
            device=args.device,
            protocol=args.protocol,
            eval_id=eval_id,
        )
        rows.append(row)

        # Write CSV after each run (incremental — don't lose data if later runs fail)
        write_csv(rows, args.output)
        print(f"  CSV updated: {args.output}")

    print_summary(rows)
    print(f"Final CSV: {args.output}")


if __name__ == "__main__":
    main()
