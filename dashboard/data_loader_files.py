"""File-backed dashboard loader, retained ONLY for the cutover parity gate.

Frozen copy of `data_loader.py` as it existed before the Postgres cutover.
`scripts/snapshot_api.py` imports this module to capture pre-cutover JSON
that can be deep-eq'd against the SQL-backed responses (rollout step 5.5).

Do not import this module from production code paths — `dashboard/app.py`
uses the SQL-backed `data_loader.py`. Delete this file after the cutover
window closes.
"""

import json
import os
import re
import sys
from datetime import datetime

DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(DASHBOARD_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from evals.resolve_run import list_runs, resolve_run
from evals.eval_research_quality import score_session


def _get_protocol_crash_comparator(protocol: str):
    """Get dynamic protocol-specific crash comparator function."""
    if protocol == "bt":
        try:
            from upstream.utils.target_device.esp32_bt import are_bt_crashes_equivalent
            return are_bt_crashes_equivalent
        except ImportError:
            pass
    return lambda id1, id2: id1 == id2



def read_jsonl(path: str) -> list[dict]:
    """Read a JSONL file, silently skipping any malformed line.

    The skip-any-malformed behavior (not just trailing-only) is intentional and
    documented: workers stream files via rsync while they are being appended,
    so the master may briefly observe a half-written final line. The same
    tolerance handles the rare case of mid-file corruption — that case is NOT
    raised to the caller. If you need stricter trailing-only tolerance, add a
    new helper rather than tightening this one.
    """
    records = []
    if not path or not os.path.exists(path):
        return records
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return records


def _normalize_sweep_manifest(manifest: dict, manifest_path: str) -> dict:
    """Rewrite results_path / progress_path inside a sweep manifest to point
    at the manifest's own directory. After rsync, those files live next to
    the manifest regardless of which worker host produced it.
    """
    base = os.path.dirname(manifest_path)
    out = dict(manifest)
    if manifest.get("results_path"):
        out["results_path"] = os.path.join(base, "results.jsonl")
    if manifest.get("progress_path"):
        out["progress_path"] = os.path.join(base, "progress.jsonl")
    return out


def read_text(path: str) -> str:
    if not path or not os.path.exists(path):
        return ""
    with open(path) as f:
        return f.read()


_LOG_LINE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)")


def parse_reasoning(app_log_path: str) -> list[dict]:
    """Extract [REASONING] blocks from the app log file."""
    if not app_log_path or not os.path.exists(app_log_path):
        return []

    blocks: list[dict] = []
    current_ts: str | None = None
    current_lines: list[str] = []
    in_reasoning = False

    with open(app_log_path) as f:
        for line in f:
            ts_match = _LOG_LINE_RE.match(line)
            if ts_match:
                if in_reasoning and current_lines:
                    blocks.append(
                        {
                            "timestamp": current_ts,
                            "content": "\n".join(current_lines).strip(),
                        }
                    )
                    current_lines = []
                    in_reasoning = False

                if "[REASONING]" in line:
                    current_ts = ts_match.group(1)
                    after = line.split("[REASONING]", 1)[1].strip()
                    if after:
                        current_lines.append(after)
                    in_reasoning = True
            elif in_reasoning:
                current_lines.append(line.rstrip())

    if in_reasoning and current_lines:
        blocks.append(
            {
                "timestamp": current_ts,
                "content": "\n".join(current_lines).strip(),
            }
        )

    return blocks


def compute_summary(info: dict, metrics: list[dict], tests: list[dict]) -> dict:
    ts_raw = info.get("timestamp", "")
    try:
        dt = datetime.strptime(ts_raw, "%Y%m%d-%H%M%S")
        start_time = dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        start_time = ts_raw

    total_turns = len(metrics)

    if metrics:
        last = metrics[-1]
        first_ts = metrics[0].get("timestamp", 0)
        last_ts = last.get("timestamp", 0)
        duration_sec = last_ts - first_ts if first_ts and last_ts else 0
        duration_min = round(duration_sec / 60, 1)
        total_crashes = last.get("cumulative_crashes", 0)
        unique_crashes = last.get("session_unique_crashes", 0)
        publicly_known = last.get("cumulative_publicly_known", 0)
        non_publicly_known = last.get("cumulative_non_publicly_known", 0)
        fully_novel = last.get("cumulative_fully_novel", 0)
        total_input_tokens = last.get("cumulative_input_tokens", 0)
        total_output_tokens = last.get("cumulative_output_tokens", 0)
    else:
        duration_min = 0
        total_crashes = unique_crashes = publicly_known = 0
        non_publicly_known = fully_novel = 0
        total_input_tokens = total_output_tokens = 0

    total_tokens = total_input_tokens + total_output_tokens
    tests_run = len(tests)
    compile_failures = sum(1 for t in tests if not t.get("compile_success", True))

    return {
        "start_time": start_time,
        "duration_min": duration_min,
        "total_turns": total_turns,
        "tests_run": tests_run,
        "compile_failures": compile_failures,
        "total_crashes": total_crashes,
        "unique_crashes": unique_crashes,
        "publicly_known": publicly_known,
        "non_publicly_known": non_publicly_known,
        "fully_novel": fully_novel,
        "total_tokens": total_tokens,
        "total_input_tokens": total_input_tokens,
        "total_output_tokens": total_output_tokens,
    }


SWEEP_LOG_ROOT = os.path.join(AGENT_DIR, "sweep_logs")


# ── Sweep data loading ──────────────────────────────────────────────


def _find_sweep_manifest(sweep_id: str) -> str | None:
    """Locate `<sweep_id>/manifest.json` across every host subdir.

    Returns the first match. Falls back to legacy flat layouts (no host
    prefix) so a partially-migrated tree still works.
    """
    if not os.path.isdir(SWEEP_LOG_ROOT):
        return None
    # Host-namespaced layout: sweep_logs/<host>/<sweep_id>/manifest.json
    for host in os.listdir(SWEEP_LOG_ROOT):
        host_dir = os.path.join(SWEEP_LOG_ROOT, host)
        if not os.path.isdir(host_dir):
            continue
        p = os.path.join(host_dir, sweep_id, "manifest.json")
        if os.path.isfile(p):
            return p
    # Legacy flat layouts (pre-migration).
    p = os.path.join(SWEEP_LOG_ROOT, sweep_id, "manifest.json")
    if os.path.isfile(p):
        return p
    p = os.path.join(SWEEP_LOG_ROOT, f"{sweep_id}_manifest.json")
    if os.path.isfile(p):
        return p
    return None


def _iter_sweep_manifest_paths() -> list[str]:
    """Enumerate every sweep manifest under SWEEP_LOG_ROOT (host-namespaced
    plus legacy flat layouts)."""
    paths: list[str] = []
    if not os.path.isdir(SWEEP_LOG_ROOT):
        return paths
    for host_entry in os.listdir(SWEEP_LOG_ROOT):
        host_dir = os.path.join(SWEEP_LOG_ROOT, host_entry)
        if os.path.isdir(host_dir):
            # Could be a host subdir (preferred) or — legacy — a sweep_id dir
            # at the root. Both contain a manifest.json directly inside their
            # children, so walk one extra level.
            inner_manifest = os.path.join(host_dir, "manifest.json")
            if os.path.isfile(inner_manifest):
                # Legacy flat: sweep_logs/<sweep_id>/manifest.json
                paths.append(inner_manifest)
                continue
            for sub in os.listdir(host_dir):
                m = os.path.join(host_dir, sub, "manifest.json")
                if os.path.isfile(m):
                    paths.append(m)
        elif host_entry.endswith("_manifest.json"):
            # Legacy flat: sweep_logs/<sweep_id>_manifest.json
            full = os.path.join(SWEEP_LOG_ROOT, host_entry)
            if os.path.isfile(full):
                paths.append(full)
    return paths


def list_sweeps() -> list[dict]:
    """Find all sweep manifests in sweep_logs/, across every host subdir."""
    result = []
    seen: set[str] = set()

    for path in _iter_sweep_manifest_paths():
        try:
            with open(path) as f:
                m = json.load(f)
            sid = m.get("sweep_id", "")
            if not sid or sid in seen:
                continue
            seen.add(sid)
            result.append(
                {
                    "sweep_id": sid,
                    "modem": m.get("modem", ""),
                    "profile": m.get("profile", ""),
                    "total_combinations": m.get("total_combinations", 0),
                    "start_time": m.get("start_time", ""),
                    "retry_of": m.get("retry_of"),
                }
            )
        except (json.JSONDecodeError, OSError):
            continue
    result.sort(key=lambda x: x["start_time"], reverse=True)
    return result


def load_sweep_data(sweep_id: str) -> dict | None:
    """Load sweep manifest, results, progress, and compute heatmap grids."""
    manifest_path = _find_sweep_manifest(sweep_id)
    if not manifest_path:
        return None

    with open(manifest_path) as f:
        manifest = json.load(f)
    # Rewrite worker-side absolute paths into manifest-dir-relative paths so
    # the master can read results.jsonl / progress.jsonl regardless of which
    # host produced the manifest.
    manifest = _normalize_sweep_manifest(manifest, manifest_path)

    results_path = manifest.get("results_path", "")
    progress_path = manifest.get("progress_path", "")

    own_results = read_jsonl(results_path)
    progress_records = read_jsonl(progress_path)

    # Check for retry chain — use merged results for heatmap/crashes
    from sweep_scripts_202604.plan import find_retry_chain, load_final_results

    retry_chain_ids = find_retry_chain(sweep_id)
    if retry_chain_ids:
        merged_results = load_final_results(sweep_id)
    else:
        merged_results = own_results

    # Progress uses own results (not merged) to avoid misrepresenting in-flight retries
    results = merged_results

    # Latest progress snapshot — use actual results count since progress.jsonl
    # is only written every 10 tests and can be stale
    total_combinations = manifest.get("total_combinations", 0)
    actual_completed = len(own_results)
    actual_crashes = sum(1 for r in merged_results if r.get("crash"))
    protocol = manifest.get("protocol") or "fiveg"
    comparator = _get_protocol_crash_comparator(protocol)
    unique_set = []
    for r in merged_results:
        if r.get("crash") and r.get("crash_id"):
            c_id = r["crash_id"]
            if not any(comparator(existing, c_id) for existing in unique_set):
                unique_set.append(c_id)
    actual_unique = len(unique_set)


    if progress_records:
        progress = progress_records[-1]
        # Override with actual counts from results.jsonl
        progress["tests_completed"] = max(
            progress.get("tests_completed", 0), actual_completed
        )
        progress["tests_remaining"] = total_combinations - progress["tests_completed"]
        progress["crashes_found"] = actual_crashes
        progress["unique_crash_ids"] = actual_unique
    else:
        progress = {
            "tests_completed": actual_completed,
            "tests_total": total_combinations,
            "tests_remaining": total_combinations - actual_completed,
            "crashes_found": actual_crashes,
            "unique_crash_ids": actual_unique,
            "elapsed_seconds": 0,
            "avg_seconds_per_test": 0,
            "eta_seconds": 0,
            "eta_hours": 0,
        }

    # Compute timing from results if progress is stale
    if results and not progress.get("avg_seconds_per_test"):
        times = [
            r["execution_time_seconds"]
            for r in results
            if r.get("execution_time_seconds")
        ]
        if times:
            progress["avg_seconds_per_test"] = round(sum(times) / len(times), 1)

    # Build heatmap grids per filter (server-side for performance)
    heatmap: dict[str, dict] = {}
    filters = manifest.get("filters", [])
    values = manifest.get("values", [])

    # Index results by (filter, offset, value)
    result_map: dict[tuple[str, int, int], dict] = {}
    for r in results:
        key = (r.get("filter", ""), r.get("offset", 0), r.get("value", 0))
        result_map[key] = r

    # Reconstruct planned offsets per filter from manifest config
    from sweep_scripts_202604.config import SweepConfig
    from sweep_scripts_202604.plan import generate_test_plan

    try:
        sweep_cfg = SweepConfig(
            sweep_id=sweep_id,
            device=manifest.get("device") or manifest.get("modem", "mediatek"),
            protocol=manifest.get("protocol", "fiveg"),
            profile=manifest.get("profile", "quick"),
            filters=filters,
            offset_range=tuple(manifest.get("offset_range", [0, 100])),
            offsets_per_filter=manifest.get("offsets_per_filter", 10),
            offset_strategy=manifest.get("offset_strategy", "near_known"),
            values=values,
        )
        full_plan = generate_test_plan(sweep_cfg)
        planned_offsets: dict[str, list[int]] = {}
        for f, o, _v in full_plan:
            planned_offsets.setdefault(f, set()).add(o)
        planned_offsets = {f: sorted(offs) for f, offs in planned_offsets.items()}
    except Exception:
        planned_offsets = {}

    for filt in filters:
        filt_results = [r for r in results if r.get("filter") == filt]
        tested_offsets = {r["offset"] for r in filt_results if "offset" in r}
        planned = set(planned_offsets.get(filt) or [])

        # Prefer planned ∪ tested when plan replay is healthy (so untested cells
        # show as null for in-progress sweeps). Fall back to actual tested
        # offsets when planning is unavailable OR has drifted (no overlap with
        # tested results — e.g. `near_known` replay after the crash DB changed).
        if planned and (not tested_offsets or tested_offsets & planned):
            offsets = sorted(planned | tested_offsets)
        else:
            offsets = sorted(tested_offsets)
        if not offsets:
            continue

        # Build grid: rows=offsets, cols=values
        # null=untested, 0=no crash, 1=crash, -1=compile fail
        grid = []
        for offset in offsets:
            row = []
            for val in values:
                r = result_map.get((filt, offset, val))
                if r is None:
                    row.append(None)
                elif not r.get("compile_success", True):
                    row.append(-1)
                elif r.get("crash"):
                    row.append(1)
                else:
                    row.append(0)
            grid.append(row)

        heatmap[filt] = {
            "offsets": offsets,
            "values": values,
            "values_hex": [f"0x{v:02X}" for v in values],
            "grid": grid,
        }

    # Crash list
    crashes = [r for r in results if r.get("crash")]

    # Build retry chain info
    retry_chain = []
    for child_id in retry_chain_ids:
        child_manifest_path = _find_sweep_manifest(child_id)
        if child_manifest_path:
            with open(child_manifest_path) as f:
                cm = json.load(f)
            cm = _normalize_sweep_manifest(cm, child_manifest_path)
            child_results_path = cm.get("results_path", "")
            child_results = read_jsonl(child_results_path)
            child_progress = read_jsonl(cm.get("progress_path", ""))
            child_status = (
                child_progress[-1].get("status", "in_progress")
                if child_progress
                else "in_progress"
            )
            retry_chain.append(
                {
                    "sweep_id": child_id,
                    "retry_depth": cm.get("retry_depth", 1),
                    "tests_total": cm.get("total_combinations", len(child_results)),
                    "tests_completed": len(child_results),
                    "status": child_status,
                }
            )

    return {
        "sweep_id": sweep_id,
        "manifest": manifest,
        "progress": progress,
        "results": results,
        "heatmap": heatmap,
        "crashes": crashes,
        "retry_chain": retry_chain,
    }


# ── Run data loading ────────────────────────────────────────────────


def load_run_list() -> list[dict]:
    runs = list_runs()
    result = []
    for r in runs:
        ts_raw = r.get("timestamp", "")
        try:
            dt = datetime.strptime(ts_raw, "%Y%m%d-%H%M%S")
            ts_display = dt.strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            ts_display = ts_raw
        result.append(
            {
                "run_id": r.get("run_id", ""),
                "session_id": r.get("session_id", ""),
                "timestamp": ts_display,
                "timestamp_raw": ts_raw,
                "modem": r.get("modem", "mediatek"),
            }
        )
    result.sort(key=lambda x: x["timestamp_raw"], reverse=True)
    return result


def load_run_data(run_id: str) -> dict | None:
    info = resolve_run(run_id)
    if not info or not os.path.exists(info.get("metrics", "")):
        return None

    metrics = read_jsonl(info.get("metrics", ""))
    resources = read_jsonl(info.get("resources", ""))

    kb_dir = info.get("kb_dir", "")
    tests_path = os.path.join(kb_dir, "tests.jsonl") if kb_dir else ""
    findings_path = os.path.join(kb_dir, "findings.jsonl") if kb_dir else ""
    strategy_path = os.path.join(kb_dir, "strategy.md") if kb_dir else ""

    tests = read_jsonl(tests_path)
    findings = read_jsonl(findings_path)
    strategy = read_text(strategy_path)

    reasoning = parse_reasoning(info.get("app_log", ""))

    # Research quality score
    rq = {}
    if kb_dir and os.path.isdir(kb_dir):
        try:
            rq = score_session(kb_dir, device=info.get("device"))
        except Exception:
            rq = {}

    summary = compute_summary(info, metrics, tests)

    version = info.get("version", "")
    if not version:
        sid = info.get("session_id", "")
        m = re.search(r"rq1-(v[123])", sid)
        version = m.group(1) if m else "full"

    return {
        "run_id": run_id,
        "session_id": info.get("session_id", ""),
        "model": info.get("model", ""),
        "modem": info.get("modem", "mediatek"),
        "version": version,
        "summary": summary,
        "metrics": metrics,
        "resources": resources,
        "tests": tests,
        "findings": findings,
        "strategy": strategy,
        "reasoning": reasoning,
        "research_quality": rq,
    }
