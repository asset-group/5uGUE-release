"""SQL-backed dashboard loader.

Backs the FastAPI dashboard endpoints in `dashboard/app.py`. Response
shapes are unchanged from the file-backed loader (`data_loader_files.py`),
so the front-end keeps working byte-identically. Reasoning blocks are
still parsed from the rsynced app log on demand — `parse_reasoning()`
and the underlying file are not migrated.
"""

import math
import os
import re
import statistics
import sys
from datetime import datetime

DASHBOARD_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(DASHBOARD_DIR)
if AGENT_DIR not in sys.path:
    sys.path.insert(0, AGENT_DIR)

from dashboard.db import get_pool


def _get_protocol_crash_comparator(protocol: str):
    """Get dynamic protocol-specific crash comparator function."""
    if protocol == "bt":
        try:
            from upstream.utils.target_device.esp32_bt import are_bt_crashes_equivalent
            return are_bt_crashes_equivalent
        except ImportError:
            pass
    return lambda id1, id2: id1 == id2


# ─── Reasoning (file-backed — still rsynced) ────────────────────────────────


_LOG_LINE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+)")


def parse_reasoning(app_log_path: str) -> list[dict]:
    """Extract [REASONING] blocks from the app log file.

    The app log stays on the rsynced filesystem (logs/<host>/*.log);
    `run.app_log_path` in the DB tells us where.
    """
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


# ─── Helpers ────────────────────────────────────────────────────────────────


def _format_ts_str(timestamp_str: str | None) -> str:
    """Display formatting for the raw `%Y%m%d-%H%M%S` manifest timestamp.

    Mirrors the behavior of `compute_summary` in the file-backed loader so
    the dashboard's "Start Time" column does not visibly shift after the
    cutover.
    """
    if not timestamp_str:
        return ""
    try:
        dt = datetime.strptime(timestamp_str, "%Y%m%d-%H%M%S")
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return timestamp_str


def _row_to_metric(row: dict) -> dict:
    """Translate a `turn` row back to the per-turn JSONL record shape that
    `compute_summary` and the dashboard chart helpers expect."""
    ts = row.get("ts")
    return {
        "turn": row.get("turn", 0),
        "timestamp": ts.timestamp() if ts is not None else 0,
        "tools_called": row.get("tools_called") or [],
        "tool_call_count": row.get("tool_call_count") or 0,
        "tool_counts": row.get("tool_counts") or {},
        "input_tokens": row.get("input_tokens") or 0,
        "output_tokens": row.get("output_tokens") or 0,
        "cumulative_input_tokens": row.get("cumulative_input_tokens") or 0,
        "cumulative_output_tokens": row.get("cumulative_output_tokens") or 0,
        "turn_crashes": row.get("turn_crashes") or 0,
        "turn_publicly_known": row.get("turn_publicly_known") or 0,
        "turn_non_publicly_known": row.get("turn_non_publicly_known") or 0,
        "turn_fully_novel": row.get("turn_fully_novel") or 0,
        "cumulative_crashes": row.get("cumulative_crashes") or 0,
        "cumulative_publicly_known": row.get("cumulative_publicly_known") or 0,
        "cumulative_non_publicly_known": row.get("cumulative_non_publicly_known") or 0,
        "cumulative_fully_novel": row.get("cumulative_fully_novel") or 0,
        "session_unique_crashes": row.get("session_unique_crashes") or 0,
        "phase": row.get("phase") or "",
    }


def _row_to_resource(row: dict) -> dict:
    ts = row.get("ts")
    out = {
        "ts": ts.timestamp() if ts is not None else 0,
        "turn": row.get("turn", 0),
        "cpu_percent": row.get("cpu_percent"),
        "mem_rss_mb": row.get("mem_rss_mb"),
        "mem_system_percent": row.get("mem_system_percent"),
        "disk_read_mb": row.get("disk_read_mb"),
        "disk_write_mb": row.get("disk_write_mb"),
        "net_sent_mb": row.get("net_sent_mb"),
        "net_recv_mb": row.get("net_recv_mb"),
    }
    if row.get("event"):
        out["event"] = row["event"]
    if row.get("metadata"):
        out["metadata"] = row["metadata"]
    return out


def _row_to_test(row: dict) -> dict:
    return {
        "test_id": row.get("test_id"),
        "exploit_name": row.get("exploit_name"),
        "exploit_code": row.get("exploit_code"),
        "exploit_hash": row.get("exploit_hash"),
        "fuzz_description": row.get("fuzz_description"),
        "crash": row.get("crash"),
        "crash_category": row.get("crash_category"),
        "crash_id": row.get("crash_id"),
        "new_states": row.get("new_states") or 0,
        "new_transitions": row.get("new_transitions") or 0,
        "compile_success": row.get("compile_success", True),
        "execution_time_seconds": row.get("execution_time_seconds") or 0,
        "mutation_count": row.get("mutation_count") or 0,
        "mutation_parse_warnings": row.get("mutation_parse_warnings") or [],
        "total_packets": row.get("total_packets") or 0,
        "timestamp": row.get("timestamp_str") or "",
    }


def compute_summary(info: dict, metrics: list[dict], tests: list[dict]) -> dict:
    """Pure aggregation — kept identical to the file-backed loader so test
    assertions on the dashboard summary block don't shift."""
    ts_raw = info.get("timestamp", "")
    start_time = _format_ts_str(ts_raw) if ts_raw else ""

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


# ─── Run list / detail ──────────────────────────────────────────────────────


def list_runs() -> list[dict]:
    """Replacement for `evals.resolve_run.list_runs()` — DB-backed.

    Kept to preserve the existing dashboard flow that fans out to a
    full-detail load per run. Returns dict-shaped rows that mimic the
    manifest fields the file-backed dashboard used.
    """
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT run_id, session_id, host_id, device, protocol, version, model,
                       max_turns, timestamp_str, started_at, ended_at,
                       app_log_path, runtime_log_path,
                       metrics_png_path, resource_metrics_png_path
                FROM run
                ORDER BY started_at DESC NULLS LAST, run_id DESC
                """,
            )
            return list(cur.fetchall())


def load_run_list() -> list[dict]:
    runs = list_runs()
    result = []
    for r in runs:
        # Accept either the SQL column name (`timestamp_str`) or the legacy
        # manifest key (`timestamp`) so unit tests that mock list_runs with
        # manifest-shaped rows keep working.
        ts_raw = r.get("timestamp_str") or r.get("timestamp") or ""
        result.append(
            {
                "run_id": r.get("run_id", ""),
                "session_id": r.get("session_id") or "",
                "timestamp": _format_ts_str(ts_raw),
                "timestamp_raw": ts_raw,
                "device": r.get("device") or "mediatek",
                "protocol": r.get("protocol") or "fiveg",
            }
        )
    result.sort(key=lambda x: x["timestamp_raw"], reverse=True)
    return result


def load_run_data(run_id: str) -> dict | None:
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "SELECT * FROM run WHERE run_id = %s",
                (run_id,),
            )
            run = cur.fetchone()
            if run is None:
                return None

            cur.execute(
                "SELECT * FROM turn WHERE run_id = %s ORDER BY turn",
                (run_id,),
            )
            turn_rows = list(cur.fetchall())

            cur.execute(
                "SELECT * FROM resource_sample WHERE run_id = %s ORDER BY ts",
                (run_id,),
            )
            resource_rows = list(cur.fetchall())

            cur.execute(
                """
                SELECT * FROM test
                WHERE run_id = %s
                ORDER BY ts NULLS LAST, test_id
                """,
                (run_id,),
            )
            test_rows = list(cur.fetchall())

            session_id = run.get("session_id") or ""
            cur.execute(
                """
                SELECT finding_id, type, description, related_tests, tags,
                       source_url, dedup_key, timestamp_str, ts
                FROM session_finding
                WHERE session_id = %s
                ORDER BY finding_id
                """,
                (session_id,),
            )
            findings_rows = list(cur.fetchall())

            cur.execute(
                "SELECT text FROM session_strategy WHERE session_id = %s",
                (session_id,),
            )
            strat_row = cur.fetchone()

    metrics = [_row_to_metric(r) for r in turn_rows]
    resources = [_row_to_resource(r) for r in resource_rows]
    tests = [_row_to_test(r) for r in test_rows]
    findings = []
    for fr in findings_rows:
        entry = {
            "finding_id": fr.get("finding_id"),
            "type": fr.get("type"),
            "description": fr.get("description"),
            "related_tests": fr.get("related_tests") or [],
            "tags": fr.get("tags") or [],
            "timestamp": fr.get("timestamp_str") or "",
        }
        if fr.get("source_url"):
            entry["source_url"] = fr["source_url"]
        if fr.get("dedup_key"):
            entry["dedup_key"] = fr["dedup_key"]
        findings.append(entry)

    strategy = strat_row["text"] if strat_row else ""
    reasoning = parse_reasoning(run.get("app_log_path") or "")

    # Research quality — DB-backed scorer reads tests + findings from SQL.
    rq: dict = {}
    try:
        from evals.eval_research_quality import score_session_db

        rq = score_session_db(session_id, device=run.get("device")) or {}
    except Exception:
        rq = {}

    info = {
        "session_id": session_id,
        "model": run.get("model") or "",
        "device": run.get("device") or "mediatek",
        "protocol": run.get("protocol") or "fiveg",
        "version": run.get("version") or "",
        "timestamp": run.get("timestamp_str") or "",
    }
    summary = compute_summary(info, metrics, tests)

    version = info["version"]
    if not version:
        m = re.search(r"rq1-(v[123])", session_id or "")
        version = m.group(1) if m else "full"

    return {
        "run_id": run_id,
        "session_id": session_id,
        "model": info["model"],
        "device": info["device"],
        "protocol": info["protocol"],
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


# ─── Sweep list / detail ────────────────────────────────────────────────────


def list_sweeps() -> list[dict]:
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT sweep_id, device, protocol, profile, total_combinations,
                       start_time_str, retry_of
                FROM sweep
                ORDER BY started_at DESC NULLS LAST, sweep_id DESC
                """,
            )
            rows = list(cur.fetchall())
    return [
        {
            "sweep_id": r.get("sweep_id", ""),
            "device": r.get("device") or "",
            "protocol": r.get("protocol") or "",
            "profile": r.get("profile") or "",
            "total_combinations": r.get("total_combinations") or 0,
            "start_time": r.get("start_time_str") or "",
            "retry_of": r.get("retry_of"),
        }
        for r in rows
    ]


def _sweep_test_to_record(row: dict) -> dict:
    """Reproduce the JSONL shape of a sweep results row for the dashboard."""
    return {
        "sweep_id": row.get("sweep_id"),
        "test_num": row.get("test_num"),
        "filter": row.get("filter"),
        "offset": row.get("offset"),
        "value": row.get("value"),
        "value_hex": row.get("value_hex"),
        "crash": row.get("crash"),
        "crash_id": row.get("crash_id"),
        "crash_category": row.get("crash_category"),
        "compile_success": row.get("compile_success", True),
        "compile_error": row.get("compile_error"),
        "execution_time_seconds": row.get("execution_time_seconds") or 0,
        "mutation_count": row.get("mutation_count") or 0,
        "total_packets": row.get("total_packets") or 0,
        "timestamp": row.get("timestamp_str") or "",
    }


def _sweep_manifest_from_row(row: dict) -> dict:
    """Reproduce the manifest dict the file-backed dashboard returns."""
    offset_range = row.get("offset_range")
    if (
        offset_range
        and hasattr(offset_range, "lower")
        and hasattr(offset_range, "upper")
    ):
        offset_range_list = [offset_range.lower, offset_range.upper]
    else:
        offset_range_list = list(offset_range) if offset_range else [0, 100]
    manifest = {
        "sweep_id": row.get("sweep_id"),
        "device": row.get("device"),
        "protocol": row.get("protocol"),
        "profile": row.get("profile"),
        "filters": row.get("filters") or [],
        "offset_range": offset_range_list,
        "offsets_per_filter": row.get("offsets_per_filter"),
        "offset_strategy": row.get("offset_strategy"),
        "values": row.get("values") or [],
        "values_hex": row.get("values_hex") or [],
        "total_combinations": row.get("total_combinations"),
        "exploit_timeout": row.get("exploit_timeout"),
        "start_time": row.get("start_time_str") or "",
    }
    if row.get("retry_of"):
        manifest["retry_of"] = row["retry_of"]
        manifest["retry_depth"] = row.get("retry_depth")
    return manifest


def load_sweep_data(sweep_id: str) -> dict | None:
    """Load a sweep, its merged retry-chain results, and heatmap grids.

    Retry-chain semantics match `sweep_scripts_202604/plan.find_retry_chain`
    + `load_final_results`: walk forward (descendants only) from the queried
    sweep, overwrite by chain depth so a child wins over its parent for the
    same (filter, offset, value).
    """
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT * FROM sweep WHERE sweep_id = %s", (sweep_id,))
            sweep_row = cur.fetchone()
            if sweep_row is None:
                return None

            # Recursive descendants from the queried node.
            cur.execute(
                """
                WITH RECURSIVE descendants AS (
                    SELECT sweep_id, retry_of, 0 AS depth
                    FROM sweep WHERE sweep_id = %s
                    UNION ALL
                    SELECT s.sweep_id, s.retry_of, d.depth + 1
                    FROM sweep s
                    JOIN descendants d ON s.retry_of = d.sweep_id
                )
                SELECT sweep_id, depth FROM descendants
                """,
                (sweep_id,),
            )
            chain = list(cur.fetchall())
            chain_ids = [c["sweep_id"] for c in chain]
            depth_by_id = {c["sweep_id"]: c["depth"] for c in chain}

            # Merged tests across descendants — pulled with depth so we can
            # dedupe by max depth per (filter, offset, value) in Python. The
            # depth-aware overwrite mirrors load_final_results in the file-
            # backed implementation.
            cur.execute(
                """
                SELECT * FROM sweep_test
                WHERE sweep_id = ANY(%s)
                ORDER BY sweep_id, test_num
                """,
                (chain_ids,),
            )
            all_test_rows = list(cur.fetchall())

            cur.execute(
                """
                SELECT * FROM sweep_progress
                WHERE sweep_id = %s
                ORDER BY ts
                """,
                (sweep_id,),
            )
            progress_rows = list(cur.fetchall())

            # Own results (queried node only) for actual_completed.
            cur.execute(
                "SELECT count(*) AS n FROM sweep_test WHERE sweep_id = %s",
                (sweep_id,),
            )
            own_count_row = cur.fetchone() or {"n": 0}

            # Per-child rows for retry_chain[] response shape.
            child_summaries: list[dict] = []
            for child_id, depth in depth_by_id.items():
                if child_id == sweep_id:
                    continue
                cur.execute(
                    "SELECT count(*) AS n FROM sweep_test WHERE sweep_id = %s",
                    (child_id,),
                )
                completed_row = cur.fetchone() or {"n": 0}
                cur.execute(
                    """
                    SELECT total_combinations, retry_depth FROM sweep
                    WHERE sweep_id = %s
                    """,
                    (child_id,),
                )
                cm = cur.fetchone() or {}
                cur.execute(
                    """
                    SELECT status FROM sweep_progress
                    WHERE sweep_id = %s
                    ORDER BY ts DESC LIMIT 1
                    """,
                    (child_id,),
                )
                last_progress = cur.fetchone() or {}
                child_summaries.append(
                    {
                        "sweep_id": child_id,
                        "retry_depth": cm.get("retry_depth", depth),
                        "tests_total": cm.get("total_combinations")
                        or completed_row["n"],
                        "tests_completed": completed_row["n"],
                        "status": last_progress.get("status") or "in_progress",
                    }
                )

    manifest = _sweep_manifest_from_row(sweep_row)

    # Merge: latest-wins on (filter, offset, value), where "latest" = max depth.
    combo_to_depth: dict[tuple, int] = {}
    combo_to_row: dict[tuple, dict] = {}
    for r in all_test_rows:
        key = (r.get("filter"), r.get("offset"), r.get("value"))
        d = depth_by_id.get(r.get("sweep_id"), 0)
        if key not in combo_to_depth or d > combo_to_depth[key]:
            combo_to_depth[key] = d
            combo_to_row[key] = r
    merged_results = [_sweep_test_to_record(r) for r in combo_to_row.values()]
    results = merged_results

    actual_completed = own_count_row["n"]
    actual_crashes = sum(1 for r in merged_results if r.get("crash"))
    protocol = sweep_row.get("protocol") or "fiveg"
    comparator = _get_protocol_crash_comparator(protocol)
    unique_set = []
    for r in merged_results:
        if r.get("crash") and r.get("crash_id"):
            c_id = r["crash_id"]
            if not any(comparator(existing, c_id) for existing in unique_set):
                unique_set.append(c_id)
    actual_unique = len(unique_set)

    total_combinations = manifest.get("total_combinations") or 0

    if progress_rows:
        last = progress_rows[-1]
        progress = {
            "tests_completed": max(last.get("tests_completed") or 0, actual_completed),
            "tests_total": last.get("tests_total") or total_combinations,
            "tests_remaining": total_combinations
            - max(last.get("tests_completed") or 0, actual_completed),
            "crashes_found": actual_crashes,
            "unique_crash_ids": actual_unique,
            "elapsed_seconds": last.get("elapsed_seconds") or 0,
            "avg_seconds_per_test": last.get("avg_seconds_per_test") or 0,
            "eta_seconds": last.get("eta_seconds") or 0,
            "eta_hours": last.get("eta_hours") or 0,
            "status": last.get("status"),
            "timestamp": last.get("timestamp_str") or "",
        }
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

    if results and not progress.get("avg_seconds_per_test"):
        times = [
            r["execution_time_seconds"]
            for r in results
            if r.get("execution_time_seconds")
        ]
        if times:
            progress["avg_seconds_per_test"] = round(sum(times) / len(times), 1)

    # Heatmap grid construction — ported verbatim from the file-backed loader
    # (this is pure data transformation, cheap, and already battle-tested).
    heatmap: dict[str, dict] = {}
    filters = manifest.get("filters", [])
    values = manifest.get("values", [])

    result_map: dict[tuple[str, int, int], dict] = {}
    for r in results:
        key = (r.get("filter", ""), r.get("offset", 0), r.get("value", 0))
        result_map[key] = r

    from sweep_scripts_202604.config import SweepConfig
    from sweep_scripts_202604.plan import generate_test_plan

    try:
        sweep_cfg = SweepConfig(
            sweep_id=sweep_id,
            modem=manifest.get("modem", "mediatek"),
            profile=manifest.get("profile", "quick"),
            filters=filters,
            offset_range=tuple(manifest.get("offset_range") or [0, 100]),
            offsets_per_filter=manifest.get("offsets_per_filter") or 10,
            offset_strategy=manifest.get("offset_strategy") or "near_known",
            values=values,
        )
        full_plan = generate_test_plan(sweep_cfg)
        planned_offsets: dict = {}
        for f, o, _v in full_plan:
            planned_offsets.setdefault(f, set()).add(o)
        planned_offsets = {f: sorted(offs) for f, offs in planned_offsets.items()}
    except Exception:
        planned_offsets = {}

    for filt in filters:
        filt_results = [r for r in results if r.get("filter") == filt]
        tested_offsets = {r["offset"] for r in filt_results if "offset" in r}
        planned = set(planned_offsets.get(filt) or [])

        if planned and (not tested_offsets or tested_offsets & planned):
            offsets = sorted(planned | tested_offsets)
        else:
            offsets = sorted(tested_offsets)
        if not offsets:
            continue

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

    crashes = [r for r in results if r.get("crash")]

    return {
        "sweep_id": sweep_id,
        "manifest": manifest,
        "progress": progress,
        "results": results,
        "heatmap": heatmap,
        "crashes": crashes,
        "retry_chain": child_summaries,
    }


# ─── Reports (multi-run eval CSVs) ──────────────────────────────────────────
# A "report" is one eval CSV produced by rq_scripts/run_eval_rq1.py — N
# independent agent runs with the same config (model/version/modem/max_turns).
# Rows are grouped by `eval_id`, a uuid4().hex stamped at CSV-write time and
# also persisted to the evaluation table.

_REPORT_NUMERIC_COLS = (
    "rq_mean_score",
    "rq_max_score",
    "total_crashes",
    "unique_crashes",
    "unique_novel",
    "total_tests",
    "time_to_first_crash_seconds",
    "total_session_time_seconds",
    "total_input_tokens",
    "total_output_tokens",
    "tests_till_first_crash",
)

# Columns where NULL means "no crash occurred", not "value is zero". Aggregates
# must filter these rows out *and* report how many were excluded so the UI can
# distinguish "fast" from "never".
_REPORT_OPTIONAL_COLS = (
    "time_to_first_crash_seconds",
    "tests_till_first_crash",
)


def _safe_stats(values: list) -> dict | None:
    """Mean/median/min/max/stdev over a numeric list, ignoring None and
    non-numeric. Returns None if no numeric values remain."""
    nums = [
        float(v)
        for v in values
        if v is not None
        and isinstance(v, (int, float))
        and not (isinstance(v, float) and math.isnan(v))
    ]
    if not nums:
        return None
    return {
        "n": len(nums),
        "mean": round(statistics.fmean(nums), 4),
        "median": round(statistics.median(nums), 4),
        "min": min(nums),
        "max": max(nums),
        "stdev": round(statistics.stdev(nums), 4) if len(nums) > 1 else 0.0,
    }


def list_reports() -> list[dict]:
    """One row per eval_id grouping in the evaluation table."""
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    eval_id,
                    max(source_csv_path)             AS source_csv_path,
                    count(*)                         AS n_runs,
                    max(version)                     AS version,
                    max(model)                       AS model,
                    max(device)                      AS device,
                    max(protocol)                    AS protocol,
                    max(max_turns)                   AS max_turns,
                    min(evaluated_at)                AS evaluated_at,
                    avg(rq_mean_score)               AS mean_rq_mean,
                    max(rq_max_score)                AS max_rq_max,
                    sum(total_crashes)               AS sum_crashes,
                    sum(unique_crashes)              AS sum_unique_crashes,
                    sum(unique_novel)                AS sum_unique_novel,
                    avg(total_session_time_seconds)  AS avg_session_seconds
                FROM evaluation
                WHERE eval_id IS NOT NULL
                GROUP BY eval_id
                ORDER BY evaluated_at DESC NULLS LAST, eval_id
                """,
            )
            rows = list(cur.fetchall())

    out = []
    for r in rows:
        csv_path = r.get("source_csv_path") or ""
        out.append(
            {
                "eval_id": r.get("eval_id"),
                "source_csv_path": csv_path,
                "source_csv_basename": os.path.basename(csv_path) if csv_path else "",
                "n_runs": r.get("n_runs") or 0,
                "version": r.get("version") or "",
                "model": r.get("model") or "",
                "device": r.get("device") or "",
                "protocol": r.get("protocol") or "",
                "max_turns": r.get("max_turns"),
                "evaluated_at": r.get("evaluated_at").isoformat()
                if r.get("evaluated_at")
                else "",
                "mean_rq_mean": float(r["mean_rq_mean"])
                if r.get("mean_rq_mean") is not None
                else None,
                "max_rq_max": r.get("max_rq_max"),
                "sum_crashes": r.get("sum_crashes") or 0,
                "sum_unique_crashes": r.get("sum_unique_crashes") or 0,
                "sum_unique_novel": r.get("sum_unique_novel") or 0,
                "avg_session_seconds": float(r["avg_session_seconds"])
                if r.get("avg_session_seconds") is not None
                else None,
            }
        )
    return out


def load_report_data(eval_id: str) -> dict | None:
    """All rows of one report + per-column aggregates + RQ level histogram."""
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT evaluation.*, run.started_at AS run_started_at
                FROM evaluation
                LEFT JOIN run ON run.run_id = evaluation.run_id
                WHERE evaluation.eval_id = %s
                ORDER BY run.started_at NULLS LAST,
                         evaluation.evaluated_at NULLS LAST,
                         evaluation.run_id
                """,
                (eval_id,),
            )
            rows = list(cur.fetchall())

    if not rows:
        return None

    # Shared config — take first non-empty across rows. They should all match.
    def _shared(col: str):
        for r in rows:
            v = r.get(col)
            if v not in (None, ""):
                return v
        return None

    config = {
        "model": _shared("model") or "",
        "version": _shared("version") or "",
        "device": _shared("device") or "",
        "protocol": _shared("protocol") or "",
        "max_turns": _shared("max_turns"),
    }

    source_csv_path = _shared("source_csv_path") or ""

    out_rows = []
    for r in rows:
        out_rows.append(
            {
                "run_id": r.get("run_id"),
                "session_id": r.get("session_id") or "",
                "model": r.get("model") or "",
                "version": r.get("version") or "",
                "device": r.get("device") or "",
                "protocol": r.get("protocol") or "",
                "max_turns": r.get("max_turns"),
                "actual_turns": r.get("actual_turns"),
                "rq_max_score": r.get("rq_max_score"),
                "rq_max_level": r.get("rq_max_level") or "",
                "rq_mean_score": float(r["rq_mean_score"])
                if r.get("rq_mean_score") is not None
                else None,
                "publicly_known_crashes": r.get("publicly_known_crashes") or 0,
                "non_publicly_known_crashes": r.get("non_publicly_known_crashes") or 0,
                "fully_novel_crashes": r.get("fully_novel_crashes") or 0,
                "total_crashes": r.get("total_crashes") or 0,
                "total_input_tokens": r.get("total_input_tokens") or 0,
                "total_output_tokens": r.get("total_output_tokens") or 0,
                "unique_crashes": r.get("unique_crashes"),
                "unique_novel": r.get("unique_novel"),
                "total_tests": r.get("total_tests"),
                "time_to_first_crash_seconds": r.get("time_to_first_crash_seconds"),
                "tests_till_first_crash": r.get("tests_till_first_crash"),
                "total_session_time_seconds": r.get("total_session_time_seconds"),
                "evaluated_at": r["evaluated_at"].isoformat()
                if r.get("evaluated_at")
                else "",
                "run_started_at": r["run_started_at"].isoformat()
                if r.get("run_started_at")
                else "",
            }
        )

    aggregates: dict = {}
    for col in _REPORT_NUMERIC_COLS:
        stats = _safe_stats([r.get(col) for r in out_rows])
        entry = stats or {"n": 0}
        if col in _REPORT_OPTIONAL_COLS:
            entry["n_with_value"] = entry.get("n", 0)
            entry["n_na"] = len(out_rows) - entry.get("n", 0)
        aggregates[col] = entry

    rq_levels = {}
    for r in out_rows:
        lvl = r.get("rq_max_level") or "L0"
        rq_levels[lvl] = rq_levels.get(lvl, 0) + 1

    return {
        "eval_id": eval_id,
        "source_csv_path": source_csv_path,
        "source_csv_basename": os.path.basename(source_csv_path)
        if source_csv_path
        else "",
        "n_runs": len(out_rows),
        "config": config,
        "rows": out_rows,
        "aggregates": aggregates,
        "rq_level_distribution": rq_levels,
    }
