#!/usr/bin/env python3
"""Reconciliation: file-tree counts vs Postgres row counts.

Used during shadow mode and as the gating signal between rsync-only and
the dashboard cutover. Walks the local rsynced tree on the storage
server, queries the DB, prints diffs, and exits non-zero if any diff is
non-empty.

Stages mirror `backfill_to_db.py` ordering. Should run in <30s on the
current corpus.
"""

from __future__ import annotations

import argparse
import csv
import glob
import json
import logging
import os
import re
import sys

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from dashboard.db import get_pool

logger = logging.getLogger("reconcile")

LEGACY_HOST = "_legacy"


def _read_jsonl_count(path: str) -> int:
    if not path or not os.path.exists(path):
        return 0
    n = 0
    with open(path) as f:
        for line in f:
            if line.strip():
                n += 1
    return n


def count_files(agent_path: str) -> dict:
    runtime_root = os.path.join(agent_path, "runtime_logs")
    sweep_root = os.path.join(agent_path, "sweep_logs")
    kb_root = os.path.join(agent_path, "kb")
    reports_root = os.path.join(agent_path, "reports")

    runs: list[str] = []
    turns_total = 0
    resources_total = 0

    if os.path.isdir(runtime_root):
        # Host-namespaced + legacy-flat manifests.
        manifests = sorted(
            glob.glob(os.path.join(runtime_root, "*", "*_manifest.json"))
        )
        manifests += sorted(glob.glob(os.path.join(runtime_root, "*_manifest.json")))
        for mp in manifests:
            try:
                with open(mp) as f:
                    m = json.load(f)
            except (json.JSONDecodeError, OSError):
                continue
            run_id = m.get("run_id")
            if not run_id:
                continue
            runs.append(run_id)
            d = os.path.dirname(mp)
            turns_total += _read_jsonl_count(
                os.path.join(d, f"agent_metrics_{run_id}.jsonl")
            )
            resources_total += _read_jsonl_count(
                os.path.join(d, f"resources_{run_id}.jsonl")
            )

    sweeps: list[str] = []
    sweep_tests_total = 0
    sweep_progress_total = 0
    if os.path.isdir(sweep_root):
        for host_entry in os.listdir(sweep_root):
            host_dir = os.path.join(sweep_root, host_entry)
            if os.path.isdir(host_dir):
                for sub in os.listdir(host_dir):
                    sd = os.path.join(host_dir, sub)
                    mp = os.path.join(sd, "manifest.json")
                    if not os.path.isfile(mp):
                        continue
                    try:
                        with open(mp) as f:
                            m = json.load(f)
                    except (json.JSONDecodeError, OSError):
                        continue
                    sid = m.get("sweep_id")
                    if not sid:
                        continue
                    sweeps.append(sid)
                    sweep_tests_total += _read_jsonl_count(
                        os.path.join(sd, "results.jsonl")
                    )
                    sweep_progress_total += _read_jsonl_count(
                        os.path.join(sd, "progress.jsonl")
                    )

    tests_total = 0
    findings_total = 0
    sessions: list[str] = []
    if os.path.isdir(kb_root):
        for host_entry in os.listdir(kb_root):
            if host_entry == "global":
                continue
            host_dir = os.path.join(kb_root, host_entry)
            if not os.path.isdir(host_dir):
                continue
            for session_id in os.listdir(host_dir):
                sd = os.path.join(host_dir, session_id)
                if not os.path.isdir(sd):
                    continue
                sessions.append(session_id)
                tests_total += _read_jsonl_count(os.path.join(sd, "tests.jsonl"))
                findings_total += _read_jsonl_count(os.path.join(sd, "findings.jsonl"))

    global_findings_total = _read_jsonl_count(
        os.path.join(kb_root, "global", "findings.jsonl")
    )

    eval_rows = 0
    if os.path.isdir(reports_root):
        for host_entry in os.listdir(reports_root):
            host_dir = os.path.join(reports_root, host_entry)
            if not os.path.isdir(host_dir):
                continue
            for path in glob.glob(os.path.join(host_dir, "eval_*.csv")):
                with open(path) as f:
                    for i, _ in enumerate(csv.DictReader(f)):
                        eval_rows += 1

    return {
        "run": len(set(runs)),
        "turn": turns_total,
        "resource_sample": resources_total,
        "sweep": len(set(sweeps)),
        "sweep_test": sweep_tests_total,
        "sweep_progress": sweep_progress_total,
        "test": tests_total,
        "session_finding": findings_total,
        "global_finding": global_findings_total,
        "evaluation": eval_rows,
    }


def count_db() -> dict:
    counts: dict[str, int] = {}
    queries = {
        "run": "SELECT count(*) FROM run",
        "turn": "SELECT count(*) FROM turn",
        "resource_sample": "SELECT count(*) FROM resource_sample",
        "sweep": "SELECT count(*) FROM sweep",
        "sweep_test": "SELECT count(*) FROM sweep_test",
        "sweep_progress": "SELECT count(*) FROM sweep_progress",
        "test": "SELECT count(*) FROM test",
        "session_finding": "SELECT count(*) FROM session_finding",
        "global_finding": "SELECT count(*) FROM global_finding",
        "evaluation": "SELECT count(*) FROM evaluation",
    }
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            for table, sql in queries.items():
                cur.execute(sql)
                row = cur.fetchone()
                counts[table] = row["count"] if isinstance(row, dict) else row[0]
    return counts


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--agent-path", default=os.environ.get("AGENT_PATH", AGENT_DIR))
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any diff is non-zero (default: just print)",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s [%(levelname)s] reconcile: %(message)s"
    )

    files = count_files(args.agent_path)
    db = count_db()

    print(f"{'table':<20} {'files':>8} {'db':>8} {'diff':>8}")
    print("-" * 46)
    nonzero = 0
    for table in sorted(files.keys()):
        f = files[table]
        d = db.get(table, 0)
        diff = d - f
        if diff != 0:
            nonzero += 1
        print(f"{table:<20} {f:>8} {d:>8} {diff:>+8}")

    if args.strict and nonzero:
        sys.exit(1)


if __name__ == "__main__":
    main()
