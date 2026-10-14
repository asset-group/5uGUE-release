"""Run ID resolver — central utility to map run_id to all artifact paths.

Usage:
    from evals.resolve_run import resolve_run, list_runs
    info = resolve_run("dd7a0f0a")
    # info["metrics"], info["kb_dir"], info["runtime_log"], ...

Walks across host-scoped subdirs (`<root>/<host>/...`) so the master sees
runs from every worker that synced into it.
"""

import glob
import json
import os
import sys

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(EVAL_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from constants import KB_ROOT, LOG_ROOT, RUNTIME_LOG_ROOT


def _glob_all_hosts(root: str, pattern: str) -> list[str]:
    """Glob `<pattern>` across every host subdirectory under `<root>`, plus
    the legacy flat layout where files lived directly under `<root>`.

    Returns host-scoped matches first (the post-migration layout), then any
    flat fallback matches — so a partially-migrated tree still works.
    """
    matches = glob.glob(os.path.join(root, "*", pattern))
    matches.extend(glob.glob(os.path.join(root, pattern)))
    return matches


def _normalize_manifest_paths(manifest: dict, manifest_path: str) -> dict:
    """Rewrite worker-side absolute paths in a runtime manifest to point at
    the local server-side trees.

    Manifests embed absolute paths (e.g. /root/.../runtime_logs/...) that are
    wrong on a master that synced from a different worker. After rsync the
    actual files live under <ROOT>/<host>/...; the host is derived from the
    manifest's location relative to the local RUNTIME_LOG_ROOT.

    Field → root mapping (these live under different roots, so a single
    manifest-dir-relative resolution would not work):
        runtime_log, metrics, resources → RUNTIME_LOG_ROOT/<host>/
        app_log                          → LOG_ROOT/<host>/
        kb_dir                           → KB_ROOT/<host>/

    For pre-migration flat layouts (`<RUNTIME_LOG_ROOT>/<id>_manifest.json`
    with no host segment) the manifest is left alone — its paths are already
    correct for this machine.
    """
    # Module-level constants are looked up here, not captured at def time, so
    # tests that monkeypatch them are honoured.
    rel = os.path.relpath(manifest_path, RUNTIME_LOG_ROOT)
    parts = rel.split(os.sep)
    if len(parts) < 2 or parts[0] in (".", ".."):
        # Flat layout: manifest sits directly under RUNTIME_LOG_ROOT, no host.
        return dict(manifest)
    host = parts[0]
    out = dict(manifest)
    field_to_root = (
        ("runtime_log", RUNTIME_LOG_ROOT),
        ("metrics", RUNTIME_LOG_ROOT),
        ("resources", RUNTIME_LOG_ROOT),
        ("app_log", LOG_ROOT),
        ("kb_dir", KB_ROOT),
    )
    for field, root in field_to_root:
        v = manifest.get(field)
        if not v:
            continue
        out[field] = os.path.join(root, host, os.path.basename(v.rstrip("/")))
    return out


def resolve_run(run_id: str) -> dict:
    """Resolve run_id to all artifact paths via manifest, with glob fallback."""
    # Manifest may live under any host subdir.
    matches = _glob_all_hosts(RUNTIME_LOG_ROOT, f"{run_id}_manifest.json")
    if matches:
        manifest_path = matches[0]
        with open(manifest_path) as f:
            manifest = json.load(f)
        return _normalize_manifest_paths(manifest, manifest_path)

    # No manifest — construct paths from run_id via glob across all hosts.
    info: dict = {"run_id": run_id}

    metrics = _glob_all_hosts(RUNTIME_LOG_ROOT, f"agent_metrics_{run_id}.jsonl")
    if metrics:
        info["metrics"] = metrics[0]

    resources = _glob_all_hosts(RUNTIME_LOG_ROOT, f"resources_{run_id}.jsonl")
    if resources:
        info["resources"] = resources[0]

    logs = _glob_all_hosts(RUNTIME_LOG_ROOT, f"{run_id}_run_*.log")
    if logs:
        info["runtime_log"] = logs[0]

    app_logs = _glob_all_hosts(LOG_ROOT, f"{run_id}_app_*.log")
    if app_logs:
        info["app_log"] = app_logs[0]

    kb_dirs = _glob_all_hosts(KB_ROOT, f"{run_id}-*")
    if kb_dirs:
        info["kb_dir"] = kb_dirs[0]
        info["session_id"] = os.path.basename(kb_dirs[0])

    return info


def resolve_session_to_run_id(session_id: str) -> str | None:
    """Extract run_id from session_id (it's the first 8-char hex prefix)."""
    parts = session_id.split("-", 1)
    if len(parts) >= 1 and len(parts[0]) == 8:
        try:
            int(parts[0], 16)
            return parts[0]
        except ValueError:
            return None
    return None


def list_runs() -> list[dict]:
    """List all known runs from manifests across every host subdir."""
    runs = []
    for f in sorted(_glob_all_hosts(RUNTIME_LOG_ROOT, "*_manifest.json")):
        with open(f) as fh:
            runs.append(json.load(fh))
    return runs
