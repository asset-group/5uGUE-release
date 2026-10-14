import csv
import hashlib
import json
import logging
import os
import time

from constants import CRASHES_CSV, GLOBAL_KB_PATH, KB_PATH

logger = logging.getLogger(__name__)


class KnowledgeBase:
    def __init__(self, session_id: str, enable_global_kb: bool = True):
        self.session_id = session_id
        self.enable_global_kb = enable_global_kb
        self.dir = os.path.join(KB_PATH, session_id)
        os.makedirs(self.dir, exist_ok=True)

        self.tests_path = os.path.join(self.dir, "tests.jsonl")
        self.findings_path = os.path.join(self.dir, "findings.jsonl")
        self.strategy_path = os.path.join(self.dir, "strategy.md")

        self._test_hashes: set[str] = set()
        self._finding_count = 0
        self._test_count = 0

        # Global KB
        self.global_findings_path = os.path.join(GLOBAL_KB_PATH, "findings.jsonl")
        self._global_dedup_keys: set[str] = set()
        if self.enable_global_kb:
            self._load_global_dedup_keys()

        # Load existing data
        self._load_existing()

    def _load_global_dedup_keys(self):
        if not os.path.exists(self.global_findings_path):
            return
        with open(self.global_findings_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                    dk = entry.get("dedup_key", "")
                    if dk:
                        self._global_dedup_keys.add(dk)
                except json.JSONDecodeError:
                    pass

    def _load_existing(self):
        if os.path.exists(self.tests_path):
            with open(self.tests_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    self._test_count += 1
                    h = entry.get("exploit_hash", "")
                    if h:
                        self._test_hashes.add(h)

        if os.path.exists(self.findings_path):
            with open(self.findings_path, "r") as f:
                for line in f:
                    if line.strip():
                        self._finding_count += 1

    def has_been_tested(self, exploit_hash: str) -> bool:
        return exploit_hash in self._test_hashes

    def log_test(self, test_result, fuzz_description: str):
        self._test_count += 1
        entry = {
            "test_id": test_result.test_id,
            "exploit_name": test_result.exploit_name,
            "exploit_code": test_result.exploit_code,
            "fuzz_description": fuzz_description,
            "crash": test_result.crash_triggered,
            "crash_category": test_result.crash_category,
            "crash_id": test_result.crash_id,
            "new_states": len(test_result.new_states),
            "new_transitions": len(test_result.new_transitions),
            "exploit_hash": test_result.exploit_hash,
            "compile_success": test_result.compile_success,
            "execution_time_seconds": test_result.execution_time_seconds,
            "mutation_count": getattr(test_result, "mutation_count", 0),
            "mutation_parse_warnings": getattr(
                test_result, "mutation_parse_warnings", []
            ),
            "total_packets": test_result.total_packets,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        if test_result.exploit_hash:
            self._test_hashes.add(test_result.exploit_hash)
        with open(self.tests_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        # test_id format is "<run_id>-<n>", per ExecutionEngine.execute().
        run_id = (
            str(test_result.test_id).split("-", 1)[0] if test_result.test_id else None
        )
        try:
            from ingest_client import enqueue

            enqueue("test", entry, run_id=run_id, session_id=self.session_id)
        except Exception as e:
            logger.warning(f"ingest enqueue failed (test): {e}")

        # Append to crashes.csv if crash detected
        if test_result.crash_triggered:
            self._append_crash_csv(test_result, fuzz_description)
            # Auto-promote crash to global KB
            crash_desc = (
                f"[Crash] {test_result.exploit_name}: {fuzz_description[:200]} | "
                f"crash_id={test_result.crash_id} | category={test_result.crash_category}"
            )
            crash_dedup = (
                f"crash:{test_result.crash_id}"
                if test_result.crash_id
                else f"crash:{test_result.test_id}"
            )
            self.save_global_finding(
                crash_desc,
                tags=["crash", "confirmed"],
                source_session=self.session_id,
                dedup_key=crash_dedup,
            )

    def _append_crash_csv(self, test_result, fuzz_description: str):
        try:
            write_header = (
                not os.path.exists(CRASHES_CSV) or os.path.getsize(CRASHES_CSV) == 0
            )
            with open(CRASHES_CSV, "a", newline="") as f:
                writer = csv.writer(f)
                if write_header:
                    writer.writerow(
                        [
                            "timestamp",
                            "session",
                            "test_id",
                            "exploit_name",
                            "crash_category",
                            "crash_id",
                            "mutation_count",
                            "mutation_parse_warnings",
                            "total_packets",
                            "description",
                            "exploit_cpp",
                            "log_path",
                            "replay_command",
                        ]
                    )
                exploit_name = test_result.exploit_name
                parse_warnings = getattr(test_result, "mutation_parse_warnings", [])
                writer.writerow(
                    [
                        time.strftime("%Y-%m-%d %H:%M:%S"),
                        self.session_id,
                        test_result.test_id,
                        exploit_name,
                        test_result.crash_category,
                        test_result.crash_id,
                        getattr(test_result, "mutation_count", 0),
                        "; ".join(parse_warnings) if parse_warnings else "",
                        test_result.total_packets,
                        fuzz_description,
                        test_result.log_path + f"/{exploit_name}.cpp"
                        if test_result.log_path
                        else "",
                        test_result.log_path,
                        f"bin/lte_fuzzer --EnableSimulator=false --EnableMutation=false --EnableOptimization=false --exploit={exploit_name}",
                    ]
                )
        except Exception as e:
            logger.error(f"Failed to append crash CSV: {e}")

    def save_finding(
        self,
        description: str,
        tags: list[str],
        related_tests: list[int] | None = None,
        dedup_key: str = "",
        source_url: str = "",
    ):
        self._finding_count += 1
        entry = {
            "finding_id": self._finding_count,
            "type": "observation",
            "description": description,
            "related_tests": related_tests or [],
            "tags": tags,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        if source_url:
            entry["source_url"] = source_url
        if dedup_key:
            entry["dedup_key"] = dedup_key
        with open(self.findings_path, "a") as f:
            f.write(json.dumps(entry) + "\n")

        try:
            from ingest_client import enqueue

            enqueue("finding", entry, session_id=self.session_id)
        except Exception as e:
            logger.warning(f"ingest enqueue failed (finding): {e}")

        # Auto-promote web_sourced findings to global KB
        if "web_sourced" in tags:
            if not dedup_key:
                dedup_key = (
                    "finding:" + hashlib.sha256(description.encode()).hexdigest()[:16]
                )
            self.save_global_finding(
                description, tags, source_session=self.session_id, dedup_key=dedup_key
            )

        return entry

    def query_findings(
        self,
        tag: str | None = None,
        field: str | None = None,
        include_past_sessions: bool = False,
        limit: int = 0,
    ) -> list[dict]:
        """Query stored findings by tag or description keyword.

        Args:
            tag: Filter entries containing this tag.
            field: Filter entries containing this keyword in description.
            include_past_sessions: If True, scan all past session directories under
                KB_PATH chronologically before scanning current session.
                Default is False for backward compatibility with session-isolated queries.
            limit: Maximum findings to return (returns most recent entries). 0 = unlimited.
        """
        results = []
        seen_keys: set[str] = set()

        # Build ordered list of directories to scan.
        # When include_past_sessions is True, past session folders are sorted
        # chronologically by mtime so older findings are processed first and
        # current session findings take recency priority.
        dirs_to_scan = []
        if include_past_sessions and os.path.exists(KB_PATH):
            past_dirs = []
            for s_name in os.listdir(KB_PATH):
                s_path = os.path.join(KB_PATH, s_name)
                if os.path.isdir(s_path) and s_path != self.dir:
                    past_dirs.append(s_path)
            # Sort past session directories chronologically (oldest -> newest)
            past_dirs.sort(key=lambda p: os.path.getmtime(p))
            dirs_to_scan.extend(past_dirs)

        # Current session directory is scanned last (highest recency priority)
        if self.dir not in dirs_to_scan:
            dirs_to_scan.append(self.dir)

        for d in dirs_to_scan:
            f_path = os.path.join(d, "findings.jsonl")
            if not os.path.exists(f_path):
                continue
            with open(f_path, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    # 1. Apply tag and keyword filters FIRST so non-matching
                    # entries do not consume deduplication slots.
                    if tag and tag not in entry.get("tags", []):
                        continue
                    if field and field not in entry.get("description", ""):
                        continue

                    # 2. Deduplicate using dedup_key if available, or fall back to SHA-256 slice
                    dedup_val = (
                        entry.get("dedup_key")
                        or hashlib.sha256(
                            entry.get("description", "").encode()
                        ).hexdigest()[:16]
                    )
                    if dedup_val in seen_keys:
                        continue
                    seen_keys.add(dedup_val)

                    results.append(entry)

        # Retain only the most recent N entries if limit is specified
        if limit > 0:
            results = results[-limit:]
        return results

    def get_test_history(self, limit: int = 50) -> list[dict]:
        results = []
        if not os.path.exists(self.tests_path):
            return results
        with open(self.tests_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    results.append(json.loads(line))
        return results[-limit:]

    def update_strategy(self, content: str):
        with open(self.strategy_path, "w") as f:
            f.write(content)
        try:
            from ingest_client import enqueue

            enqueue(
                "strategy",
                {"session_id": self.session_id, "text": content},
                session_id=self.session_id,
            )
        except Exception as e:
            logger.warning(f"ingest enqueue failed (strategy): {e}")

    def get_strategy(self) -> str:
        if os.path.exists(self.strategy_path):
            with open(self.strategy_path, "r") as f:
                return f.read()
        return ""

    def save_global_finding(
        self,
        description: str,
        tags: list[str],
        source_session: str = "",
        dedup_key: str = "",
    ):
        """Save a finding to the global KB with deduplication."""
        if not self.enable_global_kb:
            return None
        if dedup_key and dedup_key in self._global_dedup_keys:
            # Update timestamp only for existing entry (skip full rewrite for simplicity)
            return None
        os.makedirs(os.path.dirname(self.global_findings_path), exist_ok=True)
        entry = {
            "description": description,
            "tags": tags,
            "source_session": source_session or self.session_id,
            "dedup_key": dedup_key,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        with open(self.global_findings_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
        if dedup_key:
            self._global_dedup_keys.add(dedup_key)

        if dedup_key:
            try:
                from ingest_client import enqueue

                enqueue("global_finding", entry, session_id=self.session_id)
            except Exception as e:
                logger.warning(f"ingest enqueue failed (global_finding): {e}")
        return entry

    def get_global_findings(
        self, tag: str | None = None, limit: int = 50
    ) -> list[dict]:
        """Read global KB findings, optionally filtered by tag."""
        if not self.enable_global_kb:
            return []
        results = []
        if not os.path.exists(self.global_findings_path):
            return results
        with open(self.global_findings_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if tag and tag not in entry.get("tags", []):
                    continue
                results.append(entry)
        return results[-limit:]

    def promote_finding(self, finding_id: int) -> dict | None:
        """Promote a session finding to the global KB."""
        if not self.enable_global_kb:
            return None
        if not os.path.exists(self.findings_path):
            return None
        with open(self.findings_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if entry.get("finding_id") == finding_id:
                    desc = entry.get("description", "")
                    tags = entry.get("tags", [])
                    dedup_key = entry.get("dedup_key", "")
                    if not dedup_key:
                        dedup_key = (
                            "finding:" + hashlib.sha256(desc.encode()).hexdigest()[:16]
                        )
                    return self.save_global_finding(
                        desc, tags, source_session=self.session_id, dedup_key=dedup_key
                    )
        return None

    @property
    def test_count(self) -> int:
        return self._test_count

    @staticmethod
    def rebuild_crashes_csv(exploit_folder: str | None = None):
        """Rebuild crashes.csv from all session tests.jsonl files. Run once to backfill."""
        import glob

        from constants import CRASHES_CSV, KB_PATH

        if exploit_folder is None:
            from constants import EXPLOIT_FOLDER

            exploit_folder = EXPLOIT_FOLDER

        # Remove existing to rebuild clean
        if os.path.exists(CRASHES_CSV):
            os.remove(CRASHES_CSV)

        for tests_file in sorted(glob.glob(os.path.join(KB_PATH, "*/tests.jsonl"))):
            session_id = os.path.basename(os.path.dirname(tests_file))
            with open(tests_file, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    if not entry.get("crash"):
                        continue

                    test_id = entry.get("test_id", "")
                    exploit_name = entry.get("exploit_name", "")
                    log_path = os.path.join(
                        os.path.dirname(os.path.dirname(tests_file)),
                        "..",
                        "logs",
                        f"test_{test_id}",
                    )
                    log_path = os.path.normpath(log_path)

                    # Try to find the cpp: first in test log folder, then exploits folder
                    exploit_cpp = ""
                    if exploit_name:
                        candidate = os.path.join(log_path, f"{exploit_name}.cpp")
                        if os.path.exists(candidate):
                            exploit_cpp = candidate
                        else:
                            candidate = os.path.join(
                                exploit_folder, f"{exploit_name}.cpp"
                            )
                            if os.path.exists(candidate):
                                exploit_cpp = candidate

                    write_header = (
                        not os.path.exists(CRASHES_CSV)
                        or os.path.getsize(CRASHES_CSV) == 0
                    )
                    with open(CRASHES_CSV, "a", newline="") as cf:
                        writer = csv.writer(cf)
                        if write_header:
                            writer.writerow(
                                [
                                    "timestamp",
                                    "session",
                                    "test_id",
                                    "exploit_name",
                                    "crash_category",
                                    "crash_id",
                                    "mutation_count",
                                    "total_packets",
                                    "description",
                                    "exploit_cpp",
                                    "log_path",
                                    "replay_command",
                                ]
                            )
                        writer.writerow(
                            [
                                entry.get("timestamp", ""),
                                session_id,
                                test_id,
                                exploit_name,
                                entry.get("crash_category", ""),
                                entry.get("crash_id", ""),
                                entry.get("mutation_count", 0),
                                entry.get("total_packets", 0),
                                entry.get("fuzz_description", ""),
                                exploit_cpp,
                                log_path,
                                f"bin/lte_fuzzer --EnableSimulator=false --EnableMutation=false --EnableOptimization=false --exploit={exploit_name}"
                                if exploit_name
                                else "",
                            ]
                        )
