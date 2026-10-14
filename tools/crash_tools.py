import json
import logging
import os

logger = logging.getLogger(__name__)


def get_crash_tools(td_utils):
    tools = {}

    # --- analyze_crash_log ---
    def analyze_crash_log(params):
        log_folder = params["log_folder"]
        if not os.path.isabs(log_folder):
            log_folder = os.path.abspath(log_folder)

        monitor_filename = getattr(td_utils, "monitor_log", "monitor.1.txt")
        monitor_path = os.path.join(log_folder, monitor_filename)
        if not os.path.exists(monitor_path):
            return json.dumps({"error": f"Monitor log not found at {monitor_path}"})

        try:
            crash_ids = td_utils.crash_ids_from_trace_log(monitor_path)
            results = []
            for crash_id, ts in crash_ids:
                results.append({"crash_id": crash_id, "timestamp": ts})

            # Also extract context around crash
            with open(monitor_path, "r", encoding="utf8", errors="ignore") as f:
                content = f.read()

            crash_context = ""
            crash_id_field = getattr(td_utils, "crash_id_field", "sModemReason")
            idx = content.find(crash_id_field)
            if idx >= 0:
                crash_context = content[max(0, idx - 300) : idx + 500]

            return json.dumps(
                {
                    "crash_ids": results,
                    "crash_count": len(results),
                    "crash_context": crash_context[:1000],
                },
                indent=2,
            )
        except Exception as e:
            return json.dumps({"error": str(e)})

    tools["analyze_crash_log"] = (
        {
            "name": "analyze_crash_log",
            "description": "Parse device crash log from a test folder, extracting crash IDs and surrounding context.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "log_folder": {
                        "type": "string",
                        "description": "Absolute path to the test log folder (contains the device monitor/event log)",
                    }
                },
                "required": ["log_folder"],
            },
        },
        analyze_crash_log,
    )

    # --- compare_crashes ---
    def compare_crashes(params):
        crash_id_1 = params["crash_id_1"]
        crash_id_2 = params["crash_id_2"]
        are_equivalent = getattr(td_utils, "are_crashes_equivalent", lambda a, b: a.strip() == b.strip())
        same = are_equivalent(crash_id_1, crash_id_2)
        if not isinstance(same, bool):
            same = crash_id_1.strip() == crash_id_2.strip()
        return json.dumps(
            {
                "same_root_cause": same,
                "crash_id_1": crash_id_1,
                "crash_id_2": crash_id_2,
            }
        )



    tools["compare_crashes"] = (
        {
            "name": "compare_crashes",
            "description": "Check if two crash IDs represent the same root cause.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "crash_id_1": {"type": "string", "description": "First crash ID"},
                    "crash_id_2": {"type": "string", "description": "Second crash ID"},
                },
                "required": ["crash_id_1", "crash_id_2"],
            },
        },
        compare_crashes,
    )

    # --- read_device_log ---
    def read_device_log(params):
        log_path = params["log_path"]
        if not os.path.isabs(log_path):
            log_path = os.path.abspath(log_path)
        offset = params.get("offset", 0)
        max_lines = min(params.get("max_lines", 200), 200)

        if not os.path.exists(log_path):
            return f"File not found: {log_path}"

        with open(log_path, "r", encoding="utf8", errors="ignore") as f:
            lines = f.readlines()

        total = len(lines)
        selected = lines[offset : offset + max_lines]
        return json.dumps(
            {
                "total_lines": total,
                "offset": offset,
                "lines_returned": len(selected),
                "content": "".join(selected),
            }
        )

    tools["read_device_log"] = (
        {
            "name": "read_device_log",
            "description": "Read paginated raw device log (max 200 lines per call). Use for detailed crash analysis.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "log_path": {
                        "type": "string",
                        "description": "Absolute path to the log file (e.g. monitor.1.txt or run log)",
                    },
                    "offset": {
                        "type": "integer",
                        "description": "Line offset to start reading from (0-based)",
                    },
                    "max_lines": {
                        "type": "integer",
                        "description": "Max lines to return (capped at 200)",
                    },
                },
                "required": ["log_path"],
            },
        },
        read_device_log,
    )

    return tools
