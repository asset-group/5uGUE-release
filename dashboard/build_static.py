"""Build a self-contained static dashboard site under dashboard/build/."""

import json
import os
import shutil
import sys

DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(DASHBOARD_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from dashboard.data_loader import (
    load_run_list,
    load_run_data,
    list_sweeps,
    load_sweep_data,
)

BUILD_DIR = os.path.join(DASHBOARD_DIR, "build")
STATIC_DIR = os.path.join(DASHBOARD_DIR, "static")

# Path rewrites: FastAPI paths → static-site relative paths
REWRITES = {
    "index.html": [
        ('href="/static/style.css"', 'href="style.css"'),
        ('src="/static/app.js"', 'src="app.js"'),
    ],
    "app.js": [
        ("fetch('/api/runs')", "fetch('data/runs.json')"),
        ("fetch(`/api/runs/${runId}`)", "fetch(`data/runs/${runId}.json`)"),
        ("fetch('/api/sweeps')", "fetch('data/sweeps.json')"),
        ("fetch(`/api/sweeps/${sweepId}`)", "fetch(`data/sweeps/${sweepId}.json`)"),
    ],
}


def build():
    # Clean and create build directory
    if os.path.exists(BUILD_DIR):
        shutil.rmtree(BUILD_DIR)
    os.makedirs(BUILD_DIR)

    # Copy static assets, applying path rewrites where needed
    for filename in ("index.html", "app.js", "style.css"):
        src = os.path.join(STATIC_DIR, filename)
        if not os.path.exists(src):
            continue
        if filename in REWRITES:
            with open(src) as f:
                content = f.read()
            for old, new in REWRITES[filename]:
                content = content.replace(old, new)
            with open(os.path.join(BUILD_DIR, filename), "w") as f:
                f.write(content)
        else:
            shutil.copy2(src, BUILD_DIR)

    # Copy Cloudflare Pages worker (auth middleware)
    worker_src = os.path.join(DASHBOARD_DIR, "functions", "_worker.js")
    if os.path.exists(worker_src):
        shutil.copy2(worker_src, BUILD_DIR)

    # Build data directory
    data_dir = os.path.join(BUILD_DIR, "data")
    runs_dir = os.path.join(data_dir, "runs")
    os.makedirs(runs_dir)

    # Write runs index
    runs = load_run_list()
    with open(os.path.join(data_dir, "runs.json"), "w") as f:
        json.dump(runs, f)
    print(f"  {len(runs)} runs indexed")

    # Write per-run data
    built = 0
    for r in runs:
        run_id = r["run_id"]
        run_data = load_run_data(run_id)
        if run_data is None:
            print(f"  SKIP {run_id} (no metrics)")
            continue
        with open(os.path.join(runs_dir, f"{run_id}.json"), "w") as f:
            json.dump(run_data, f)
        built += 1

    print(f"  {built} run data files written")

    # Write sweep data
    sweeps_dir = os.path.join(data_dir, "sweeps")
    os.makedirs(sweeps_dir, exist_ok=True)
    sweeps = list_sweeps()
    with open(os.path.join(data_dir, "sweeps.json"), "w") as f:
        json.dump(sweeps, f)
    print(f"  {len(sweeps)} sweeps indexed")

    sweep_built = 0
    for s in sweeps:
        sid = s["sweep_id"]
        sdata = load_sweep_data(sid)
        if sdata is None:
            continue
        with open(os.path.join(sweeps_dir, f"{sid}.json"), "w") as f:
            json.dump(sdata, f)
        sweep_built += 1
    print(f"  {sweep_built} sweep data files written")

    print(f"  Output: {BUILD_DIR}")


if __name__ == "__main__":
    print("Building static dashboard...")
    build()
    print("Done.")
