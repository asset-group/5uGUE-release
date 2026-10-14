#!/usr/bin/env python3
"""Backfill the historical filesystem corpus into Postgres via the ingest API.

Runs on the storage server, idempotent, rerunnable. Walks the
host-namespaced trees (and the legacy flat layouts) and POSTs through
http://127.0.0.1:8000/ingest/... so validation + UPSERT semantics are
exercised the same way live workers exercise them.

Order avoids transient FK pain even though stub creation also handles it:
  1. hosts (implicit — created by the run/sweep posts)
  2. runs (manifest → POST /ingest/runs)
  3. turns (agent_metrics_<run>.jsonl)
  4. resources (resources_<run>.jsonl)
  5. tests (kb/<host>/<session>/tests.jsonl)
  6. session findings + strategy (kb/<host>/<session>/{findings.jsonl,strategy.md})
  7. global findings (kb/global/findings.jsonl)
  8. sweeps (manifest → POST /ingest/sweeps; results.jsonl + progress.jsonl)
  9. evaluations (reports/<host>/eval_*.csv rows)
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
import time
from typing import Any, Iterable

import requests

AGENT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

logger = logging.getLogger("backfill")

LEGACY_HOST = "_legacy"
BATCH_SIZE = 500


# ─── HTTP plumbing ─────────────────────────────────────────────────────────


class Ingest:
    def __init__(self, base_url: str, token: str, dry_run: bool):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.dry_run = dry_run
        self.session = requests.Session()

    def _post(
        self,
        path: str,
        body: Any,
        *,
        host_id: str | None = None,
        session_id: str | None = None,
        method: str = "POST",
    ) -> int:
        if self.dry_run:
            logger.info(
                "[dry-run] %s %s (rows=%s)",
                method,
                path,
                len(body) if isinstance(body, list) else 1,
            )
            return 200
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        if host_id:
            headers["X-Host-Id"] = host_id
        if session_id:
            headers["X-Session-Id"] = session_id
        resp = self.session.request(
            method,
            self.base_url + path,
            headers=headers,
            data=json.dumps(body),
            timeout=60.0,
        )
        if not (200 <= resp.status_code < 300):
            logger.error(
                "%s %s → %s: %s", method, path, resp.status_code, resp.text[:500]
            )
            resp.raise_for_status()
        return resp.status_code

    def post_run(self, body: dict):
        self._post("/ingest/runs", body)

    def patch_run(self, run_id: str, body: dict):
        self._post(f"/ingest/runs/{run_id}", body, method="PATCH")

    def post_turns(self, run_id: str, body: list[dict], host_id: str):
        for chunk in _chunks(body, BATCH_SIZE):
            self._post(f"/ingest/runs/{run_id}/turns", chunk, host_id=host_id)

    def post_resources(self, run_id: str, body: list[dict], host_id: str):
        for chunk in _chunks(body, BATCH_SIZE):
            self._post(f"/ingest/runs/{run_id}/resources", chunk, host_id=host_id)

    def post_tests(self, run_id: str, body: list[dict], host_id: str):
        for chunk in _chunks(body, BATCH_SIZE):
            self._post(f"/ingest/runs/{run_id}/tests", chunk, host_id=host_id)

    def post_session_findings(self, session_id: str, body: list[dict]):
        for chunk in _chunks(body, BATCH_SIZE):
            self._post("/ingest/findings", chunk, session_id=session_id)

    def post_global_findings(self, body: list[dict]):
        for chunk in _chunks(body, BATCH_SIZE):
            self._post("/ingest/global_findings", chunk)

    def post_strategy(self, body: dict):
        self._post("/ingest/strategy", body)

    def post_sweep(self, body: dict):
        self._post("/ingest/sweeps", body)

    def post_sweep_tests(self, sweep_id: str, body: list[dict], host_id: str):
        for chunk in _chunks(body, BATCH_SIZE):
            self._post(f"/ingest/sweeps/{sweep_id}/tests", chunk, host_id=host_id)

    def post_sweep_progress(self, sweep_id: str, body: list[dict], host_id: str):
        for chunk in _chunks(body, BATCH_SIZE):
            self._post(f"/ingest/sweeps/{sweep_id}/progress", chunk, host_id=host_id)

    def post_evaluations(self, body: list[dict], host_id: str):
        for chunk in _chunks(body, BATCH_SIZE):
            self._post("/ingest/evaluations", chunk, host_id=host_id)


def _chunks(seq: list[Any], n: int) -> Iterable[list[Any]]:
    for i in range(0, len(seq), n):
        yield seq[i : i + n]


def _read_jsonl(path: str) -> list[dict]:
    out: list[dict] = []
    if not path or not os.path.exists(path):
        return out
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                logger.debug("skipping malformed JSONL line in %s", path)
    return out


# ─── File discovery ────────────────────────────────────────────────────────


def find_run_manifests(
    roots: dict[str, str], include_legacy: bool
) -> list[tuple[str, str]]:
    """Return [(host_id, manifest_path)] for every run manifest."""
    runtime_root = roots["runtime_logs"]
    out: list[tuple[str, str]] = []
    if os.path.isdir(runtime_root):
        for host_entry in os.listdir(runtime_root):
            host_dir = os.path.join(runtime_root, host_entry)
            if not os.path.isdir(host_dir):
                continue
            for path in sorted(glob.glob(os.path.join(host_dir, "*_manifest.json"))):
                out.append((host_entry, path))
        if include_legacy:
            for path in sorted(
                glob.glob(os.path.join(runtime_root, "*_manifest.json"))
            ):
                out.append((LEGACY_HOST, path))
    return out


def find_sweep_manifests(
    roots: dict[str, str], include_legacy: bool
) -> list[tuple[str, str]]:
    sweep_root = roots["sweep_logs"]
    out: list[tuple[str, str]] = []
    if not os.path.isdir(sweep_root):
        return out
    for host_entry in os.listdir(sweep_root):
        host_dir = os.path.join(sweep_root, host_entry)
        if os.path.isdir(host_dir):
            inner = os.path.join(host_dir, "manifest.json")
            if include_legacy and os.path.isfile(inner):
                out.append((LEGACY_HOST, inner))
                continue
            for sub in os.listdir(host_dir):
                m = os.path.join(host_dir, sub, "manifest.json")
                if os.path.isfile(m):
                    out.append((host_entry, m))
        elif include_legacy and host_entry.endswith("_manifest.json"):
            out.append((LEGACY_HOST, os.path.join(sweep_root, host_entry)))
    return out


def find_kb_session_dirs(roots: dict[str, str]) -> list[tuple[str, str, str]]:
    """[(host_id, session_id, kb_dir)]."""
    out: list[tuple[str, str, str]] = []
    kb_root = roots["kb"]
    if not os.path.isdir(kb_root):
        return out
    for host_entry in os.listdir(kb_root):
        if host_entry == "global":
            continue
        host_dir = os.path.join(kb_root, host_entry)
        if not os.path.isdir(host_dir):
            continue
        for session_id in os.listdir(host_dir):
            sd = os.path.join(host_dir, session_id)
            if os.path.isdir(sd):
                out.append((host_entry, session_id, sd))
    return out


def find_eval_csvs(roots: dict[str, str]) -> list[tuple[str, str]]:
    """[(host_id, csv_path)]."""
    out: list[tuple[str, str]] = []
    reports_root = roots["reports"]
    if not os.path.isdir(reports_root):
        return out
    for host_entry in os.listdir(reports_root):
        host_dir = os.path.join(reports_root, host_entry)
        if not os.path.isdir(host_dir):
            continue
        for path in sorted(glob.glob(os.path.join(host_dir, "eval_*.csv"))):
            out.append((host_entry, path))
    return out


# ─── Per-record translation ────────────────────────────────────────────────


def _normalize_path_to_master(
    value: str | None, host_id: str, master_root: str
) -> str | None:
    """Translate a worker-absolute path into the master-side per-host path.

    Manifests embed worker absolute paths (e.g. <WDISSECTOR_PATH>/.../
    runtime_logs/<run>_run_<ts>.log). Post-rsync, that file actually lives on
    the master at <master_root>/<host_id>/<basename>. Without this rewrite,
    `run.app_log_path` etc. in DB point at locations that do not exist on the
    master — the same cross-host bug `evals/resolve_run.py:_normalize_manifest_paths`
    used to fix at read time.

    `_legacy` host (flat layout, no host segment) keeps the original path —
    it was already correct for the local machine.
    """
    if not value or host_id == LEGACY_HOST:
        return value
    return os.path.join(master_root, host_id, os.path.basename(value.rstrip("/")))


def manifest_to_run_payload(
    manifest: dict, host_id: str, roots: dict[str, str]
) -> dict:
    app_log = _normalize_path_to_master(manifest.get("app_log"), host_id, roots["logs"])
    runtime_log = _normalize_path_to_master(
        manifest.get("runtime_log"), host_id, roots["runtime_logs"]
    )
    metrics_png_src = _png_for(manifest, "agent_metrics")
    resources_png_src = _png_for(manifest, "resources")
    return {
        "run_id": manifest["run_id"],
        "host_id": host_id,
        "session_id": manifest.get("session_id"),
        "modem": manifest.get("modem"),
        "version": manifest.get("version"),
        "model": manifest.get("model"),
        "max_turns": manifest.get("max_turns"),
        "timestamp": manifest.get("timestamp"),
        "app_log_path": app_log,
        "runtime_log_path": runtime_log,
        "metrics_png_path": _normalize_path_to_master(
            metrics_png_src, host_id, roots["runtime_logs"]
        ),
        "resource_metrics_png_path": _normalize_path_to_master(
            resources_png_src, host_id, roots["runtime_logs"]
        ),
    }


def _png_for(manifest: dict, kind: str) -> str | None:
    """Derive the PNG path from the manifest's matching JSONL path."""
    src = manifest.get("metrics" if kind == "agent_metrics" else "resources")
    if not src:
        return None
    if src.endswith(".jsonl"):
        return src[: -len(".jsonl")] + ".png"
    return None


def run_finish_payload_from_metrics(metrics_records: list[dict]) -> dict | None:
    """Build the run_finish PATCH payload from the last agent_metrics record."""
    if not metrics_records:
        return None
    last = metrics_records[-1]
    return {
        "status": "completed",
        "final_total_crashes": last.get("cumulative_crashes", 0),
        "final_unique_crashes": last.get("session_unique_crashes", 0),
        "final_publicly_known": last.get("cumulative_publicly_known", 0),
        "final_non_publicly_known": last.get("cumulative_non_publicly_known", 0),
        "final_fully_novel": last.get("cumulative_fully_novel", 0),
        "total_input_tokens": last.get("cumulative_input_tokens", 0),
        "total_output_tokens": last.get("cumulative_output_tokens", 0),
        "ended_at": last.get("timestamp"),
    }


def manifest_to_sweep_payload(manifest: dict, host_id: str) -> dict:
    return {
        "sweep_id": manifest["sweep_id"],
        "host_id": host_id,
        "modem": manifest.get("modem"),
        "profile": manifest.get("profile"),
        "filters": manifest.get("filters"),
        "offset_range": manifest.get("offset_range"),
        "offsets_per_filter": manifest.get("offsets_per_filter"),
        "offset_strategy": manifest.get("offset_strategy"),
        "values": manifest.get("values"),
        "values_hex": manifest.get("values_hex"),
        "total_combinations": manifest.get("total_combinations"),
        "exploit_timeout": manifest.get("exploit_timeout"),
        "retry_of": manifest.get("retry_of"),
        "retry_depth": manifest.get("retry_depth"),
        "start_time": manifest.get("start_time"),
    }


# ─── Eval CSV parsing ──────────────────────────────────────────────────────

_EVAL_PATH_RE = re.compile(r"eval_(?P<version>v\d+|full)_(?P<ts>\d{8}_\d{6})\.csv$")


def _parse_eval_path(csv_path: str) -> tuple[str, float] | None:
    """Extract (version, evaluated_at_epoch) from the eval CSV filename."""
    m = _EVAL_PATH_RE.search(csv_path)
    if not m:
        return None
    try:
        ts = time.mktime(time.strptime(m.group("ts"), "%Y%m%d_%H%M%S"))
    except ValueError:
        return None
    return (m.group("version"), ts)


def csv_rows_to_eval_payloads(csv_path: str, host_id: str) -> list[dict]:
    parsed = _parse_eval_path(csv_path)
    if parsed is None:
        return []
    version_default, evaluated_at = parsed
    payloads: list[dict] = []
    with open(csv_path) as f:
        for row in csv.DictReader(f):
            run_id = (row.get("run_id") or "").strip()
            if not run_id or run_id == "N/A":
                continue
            payloads.append(
                {
                    "run_id": run_id,
                    "version": (row.get("version") or version_default),
                    "evaluated_at": evaluated_at,
                    "session_id": row.get("session_id"),
                    "model": row.get("model"),
                    "modem": row.get("modem"),
                    "max_turns": _to_int(row.get("max_turns")),
                    "actual_turns": _to_int(row.get("actual_turns")),
                    "rq_max_score": _to_int(row.get("rq_max_score")),
                    "rq_max_level": row.get("rq_max_level"),
                    "rq_mean_score": _to_float(row.get("rq_mean_score")),
                    "publicly_known_crashes": _to_int(
                        row.get("publicly_known_crashes")
                    ),
                    "non_publicly_known_crashes": _to_int(
                        row.get("non_publicly_known_crashes")
                    ),
                    "fully_novel_crashes": _to_int(row.get("fully_novel_crashes")),
                    "total_crashes": _to_int(row.get("total_crashes")),
                    "total_input_tokens": _to_int(row.get("total_input_tokens")),
                    "total_output_tokens": _to_int(row.get("total_output_tokens")),
                    "source_csv_path": csv_path,
                }
            )
    return payloads


def _to_int(v: Any) -> int | None:
    if v is None or v == "":
        return None
    try:
        return int(float(v))
    except (TypeError, ValueError):
        return None


def _to_float(v: Any) -> float | None:
    if v is None or v == "":
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


# ─── Backfill stages ───────────────────────────────────────────────────────


def backfill_runs(
    api: Ingest, roots: dict[str, str], since: str | None, include_legacy: bool
) -> set[str]:
    """Returns the set of (host_id, run_id) → run_id strings ingested."""
    seen: set[str] = set()
    for host_id, manifest_path in find_run_manifests(roots, include_legacy):
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("skipping unreadable manifest %s: %s", manifest_path, e)
            continue
        if since and (manifest.get("timestamp") or "") < since:
            continue
        run_id = manifest.get("run_id")
        if not run_id:
            continue

        api.post_run(manifest_to_run_payload(manifest, host_id, roots))
        seen.add(run_id)

        # Per-run streams.
        runtime_dir = os.path.dirname(manifest_path)
        metrics_path = os.path.join(runtime_dir, f"agent_metrics_{run_id}.jsonl")
        resources_path = os.path.join(runtime_dir, f"resources_{run_id}.jsonl")

        metrics = _read_jsonl(metrics_path)
        if metrics:
            api.post_turns(run_id, metrics, host_id)
        resources = _read_jsonl(resources_path)
        if resources:
            api.post_resources(run_id, resources, host_id)

        finish = run_finish_payload_from_metrics(metrics)
        if finish:
            api.patch_run(run_id, finish)
    return seen


def backfill_kb(api: Ingest, roots: dict[str, str]) -> None:
    """Tests + session findings + strategy from kb/<host>/<session>/."""
    for host_id, session_id, kb_dir in find_kb_session_dirs(roots):
        # Tests need a run_id. Try to derive from session_id (always
        # `<run_id>-<...>`); fall back to per-test prefix.
        m = re.match(r"^([0-9a-f]{8})", session_id)
        derived_run = m.group(1) if m else None

        tests_path = os.path.join(kb_dir, "tests.jsonl")
        tests = _read_jsonl(tests_path)
        # Group by inferred run_id (test_id prefix). Most sessions have a
        # single run, so this is usually a no-op grouping.
        by_run: dict[str, list[dict]] = {}
        for t in tests:
            tid = str(t.get("test_id", ""))
            run_id = (
                tid.split("-", 1)[0] if "-" in tid else derived_run
            ) or derived_run
            if not run_id or len(run_id) != 8:
                continue
            payload = dict(t)
            payload["session_id"] = session_id
            by_run.setdefault(run_id, []).append(payload)
        for run_id, batch in by_run.items():
            api.post_tests(run_id, batch, host_id)

        findings_path = os.path.join(kb_dir, "findings.jsonl")
        findings = _read_jsonl(findings_path)
        if findings:
            api.post_session_findings(session_id, findings)

        strategy_path = os.path.join(kb_dir, "strategy.md")
        if os.path.exists(strategy_path):
            with open(strategy_path) as f:
                text = f.read()
            api.post_strategy(
                {"session_id": session_id, "host_id": host_id, "text": text}
            )


def backfill_global_findings(api: Ingest, roots: dict[str, str]) -> None:
    path = os.path.join(roots["kb"], "global", "findings.jsonl")
    findings = _read_jsonl(path)
    deduped: dict[str, dict] = {}
    for f in findings:
        key = f.get("dedup_key") or ""
        if not key:
            continue
        deduped[key] = f
    if deduped:
        api.post_global_findings(list(deduped.values()))


def backfill_sweeps(api: Ingest, roots: dict[str, str], include_legacy: bool) -> None:
    for host_id, manifest_path in find_sweep_manifests(roots, include_legacy):
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(
                "skipping unreadable sweep manifest %s: %s", manifest_path, e
            )
            continue
        sweep_id = manifest.get("sweep_id")
        if not sweep_id:
            continue
        api.post_sweep(manifest_to_sweep_payload(manifest, host_id))

        sweep_dir = os.path.dirname(manifest_path)
        results = _read_jsonl(os.path.join(sweep_dir, "results.jsonl"))
        if results:
            api.post_sweep_tests(sweep_id, results, host_id)
        progress = _read_jsonl(os.path.join(sweep_dir, "progress.jsonl"))
        if progress:
            api.post_sweep_progress(sweep_id, progress, host_id)


def backfill_evaluations(api: Ingest, roots: dict[str, str]) -> None:
    for host_id, csv_path in find_eval_csvs(roots):
        rows = csv_rows_to_eval_payloads(csv_path, host_id)
        if rows:
            api.post_evaluations(rows, host_id)


# ─── Entry point ───────────────────────────────────────────────────────────


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--base-url",
        default="http://127.0.0.1:8000",
        help="Ingest API base URL (default: http://127.0.0.1:8000)",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("AGENT_INGEST_TOKEN"),
        help="Bearer token (default: $AGENT_INGEST_TOKEN)",
    )
    parser.add_argument(
        "--agent-path",
        default=os.environ.get("AGENT_PATH", AGENT_DIR),
        help="Agent root directory (default: $AGENT_PATH)",
    )
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument(
        "--since",
        default=None,
        help="Only backfill runs with manifest timestamp >= YYYYMMDD",
    )
    parser.add_argument(
        "--include-legacy",
        dest="include_legacy",
        action="store_true",
        default=True,
        help="Walk legacy flat layouts under _legacy host (default)",
    )
    parser.add_argument(
        "--no-include-legacy", dest="include_legacy", action="store_false"
    )
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(levelname)s] backfill: %(message)s",
    )

    if not args.token and not args.dry_run:
        print("ERROR: --token or $AGENT_INGEST_TOKEN required", file=sys.stderr)
        sys.exit(2)

    roots = {
        "runtime_logs": os.path.join(args.agent_path, "runtime_logs"),
        "sweep_logs": os.path.join(args.agent_path, "sweep_logs"),
        "logs": os.path.join(args.agent_path, "logs"),
        "kb": os.path.join(args.agent_path, "kb"),
        "reports": os.path.join(args.agent_path, "reports"),
    }
    api = Ingest(args.base_url, args.token or "", args.dry_run)

    logger.info("(1/5) runs")
    backfill_runs(api, roots, args.since, args.include_legacy)
    logger.info("(2/5) kb sessions")
    backfill_kb(api, roots)
    logger.info("(3/5) global findings")
    backfill_global_findings(api, roots)
    logger.info("(4/5) sweeps")
    backfill_sweeps(api, roots, args.include_legacy)
    logger.info("(5/5) evaluations")
    backfill_evaluations(api, roots)
    logger.info("done")


if __name__ == "__main__":
    main()
