#!/usr/bin/env python3
"""Capture file-backed dashboard JSON snapshots for the parity gate.

Used during rollout step 5.5: take a snapshot of the file-backed
`/api/runs/{run_id}` and `/api/sweeps/{sweep_id}` responses for a
representative set of runs and sweeps, BEFORE the dashboard is cut
over to the SQL-backed loader. Then diff against the SQL-backed
output to verify no functional regression.

Reads through `dashboard.data_loader_files` so it bypasses any DB
dependency. Writes one JSON file per (run|sweep) into the chosen
output directory, keyed by id.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from dashboard import data_loader_files as files_loader  # noqa: E402

logger = logging.getLogger("snapshot_api")


def snapshot(out_dir: str, run_ids: list[str], sweep_ids: list[str]) -> None:
    runs_dir = os.path.join(out_dir, "runs")
    sweeps_dir = os.path.join(out_dir, "sweeps")
    os.makedirs(runs_dir, exist_ok=True)
    os.makedirs(sweeps_dir, exist_ok=True)

    for run_id in run_ids:
        data = files_loader.load_run_data(run_id)
        if data is None:
            logger.warning("no run found for %s", run_id)
            continue
        path = os.path.join(runs_dir, f"{run_id}.json")
        with open(path, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True, default=str)
        logger.info("wrote %s", path)

    for sweep_id in sweep_ids:
        data = files_loader.load_sweep_data(sweep_id)
        if data is None:
            logger.warning("no sweep found for %s", sweep_id)
            continue
        path = os.path.join(sweeps_dir, f"{sweep_id}.json")
        with open(path, "w") as f:
            json.dump(data, f, indent=2, sort_keys=True, default=str)
        logger.info("wrote %s", path)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out-dir", required=True, help="Where to write the snapshot JSON files"
    )
    parser.add_argument(
        "--runs",
        nargs="*",
        default=[],
        help="Run IDs to snapshot (≥3 for the parity gate)",
    )
    parser.add_argument(
        "--sweeps",
        nargs="*",
        default=[],
        help="Sweep IDs to snapshot (≥2 incl. a retry chain)",
    )
    parser.add_argument(
        "--auto",
        action="store_true",
        help="Pick the most recent runs/sweeps automatically",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] snapshot_api: %(message)s",
    )

    runs = list(args.runs)
    sweeps = list(args.sweeps)
    if args.auto:
        runs += [r["run_id"] for r in files_loader.load_run_list()[:5]]
        sweeps += [s["sweep_id"] for s in files_loader.list_sweeps()[:5]]
    if not runs and not sweeps:
        print("ERROR: pass --runs/--sweeps or --auto", file=sys.stderr)
        sys.exit(2)

    snapshot(args.out_dir, runs, sweeps)


if __name__ == "__main__":
    main()
