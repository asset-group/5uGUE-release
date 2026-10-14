import json
import logging
import re
import subprocess
import time

from constants import ADB_PATH, ADB_CMD_TIMEOUT

logger = logging.getLogger(__name__)

# Module-level device serial, set by get_adb_tools(). Falls back to constants.
_adb_device_serial: str | None = None


def _run_adb(*args, timeout=ADB_CMD_TIMEOUT):
    """Run an ADB command and return (returncode, stdout, stderr).

    Always targets the configured device serial. Handles timeouts and
    missing-binary errors gracefully.
    """
    serial = _adb_device_serial
    if serial is None:
        from constants import ADB_DEVICE_SERIAL

        serial = ADB_DEVICE_SERIAL
    cmd = [ADB_PATH, "-s", serial] + list(args)
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return -1, "", f"ADB command timed out after {timeout}s: {' '.join(cmd)}"
    except FileNotFoundError:
        return -1, "", f"ADB binary not found at {ADB_PATH}"


def _filter_lines(text, grep_pattern=None, max_lines=500):
    """Apply optional regex filter and line cap to output text."""
    lines = text.splitlines()
    if grep_pattern:
        try:
            pat = re.compile(grep_pattern, re.IGNORECASE)
            lines = [l for l in lines if pat.search(l)]
        except re.error as e:
            lines = [f"[invalid grep_pattern: {e}]"] + lines
    truncated = len(lines) > max_lines
    lines = lines[:max_lines]
    return lines, truncated


def get_adb_tools(adb_serial: str | None = None):
    global _adb_device_serial
    if adb_serial is not None:
        _adb_device_serial = adb_serial
    tools = {}

    # --- adb_logcat ---
    def adb_logcat(params):
        minutes = params.get("minutes", 5)
        grep_pattern = params.get("grep_pattern", None)
        max_lines = min(params.get("max_lines", 500), 2000)

        rc, stdout, stderr = _run_adb(
            "logcat",
            "-d",
            "-t",
            f"{minutes}:00",
        )
        if rc != 0:
            return json.dumps(
                {"error": stderr or "adb logcat failed", "returncode": rc}
            )

        lines, truncated = _filter_lines(stdout, grep_pattern, max_lines)
        return json.dumps(
            {
                "line_count": len(lines),
                "truncated": truncated,
                "content": "\n".join(lines),
            }
        )

    tools["adb_logcat"] = (
        {
            "name": "adb_logcat",
            "description": "Query recent Android logcat entries from the UE. Use to check for modem errors, crashes, or state changes the oracle may have missed.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "minutes": {
                        "type": "integer",
                        "description": "How many minutes of recent logs to retrieve (default 5)",
                    },
                    "grep_pattern": {
                        "type": "string",
                        "description": "Optional regex to filter log lines (case-insensitive)",
                    },
                    "max_lines": {
                        "type": "integer",
                        "description": "Max lines to return (default 500, max 2000)",
                    },
                },
                "required": [],
            },
        },
        adb_logcat,
    )

    # --- adb_device_state ---
    def adb_device_state(params):
        props = [
            ("baseband_version", "gsm.version.baseband"),
            ("sim_state", "gsm.sim.state"),
            ("network_type", "gsm.network.type"),
            ("operator", "gsm.sim.operator.alpha"),
            ("radio_technology", "gsm.current.phone-type"),
            ("service_state", "gsm.nitz.time"),
            ("boot_completed", "sys.boot_completed"),
        ]
        result = {}
        for label, prop in props:
            rc, stdout, stderr = _run_adb("shell", "getprop", prop)
            if rc == 0:
                result[label] = stdout.strip()
            else:
                result[label] = f"error: {stderr.strip()}"

        # Uptime
        rc, stdout, stderr = _run_adb("shell", "cat", "/proc/uptime")
        if rc == 0:
            parts = stdout.strip().split()
            if parts:
                result["uptime_seconds"] = float(parts[0])

        # Telephony registry summary
        rc, stdout, stderr = _run_adb(
            "shell",
            "dumpsys",
            "telephony.registry",
        )
        if rc == 0:
            grep_pattern = params.get("grep_pattern", None)
            lines, _ = _filter_lines(
                stdout,
                grep_pattern or "mServiceState|mSignalStrength|mDataConnectionState",
                50,
            )
            result["telephony_summary"] = "\n".join(lines)

        return json.dumps(result, indent=2)

    tools["adb_device_state"] = (
        {
            "name": "adb_device_state",
            "description": "Get a full device state snapshot: baseband version, SIM state, radio type, uptime, and telephony registry summary. Use to verify the modem is alive and connected after a test.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "grep_pattern": {
                        "type": "string",
                        "description": "Optional regex to filter telephony registry lines",
                    },
                },
                "required": [],
            },
        },
        adb_device_state,
    )

    # --- adb_dmesg ---
    def adb_dmesg(params):
        grep_pattern = params.get("grep_pattern", None)
        max_lines = min(params.get("max_lines", 500), 2000)

        rc, stdout, stderr = _run_adb("shell", "dmesg")
        if rc != 0:
            return json.dumps({"error": stderr or "adb dmesg failed", "returncode": rc})

        lines, truncated = _filter_lines(stdout, grep_pattern, max_lines)
        return json.dumps(
            {
                "line_count": len(lines),
                "truncated": truncated,
                "content": "\n".join(lines),
            }
        )

    tools["adb_dmesg"] = (
        {
            "name": "adb_dmesg",
            "description": "Read kernel dmesg from the UE. Use to find modem driver crashes, kernel panics, or low-level hardware errors not visible in logcat.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "grep_pattern": {
                        "type": "string",
                        "description": "Optional regex to filter dmesg lines (case-insensitive). Try 'modem|mediatek|mtk|panic|crash|error' for modem issues.",
                    },
                    "max_lines": {
                        "type": "integer",
                        "description": "Max lines to return (default 500, max 2000)",
                    },
                },
                "required": [],
            },
        },
        adb_dmesg,
    )

    # --- adb_dumpsys ---
    ALLOWED_SERVICES = {
        "telephony.registry",
        "phone",
        "carrier_config",
        "netd",
        "connectivity",
    }

    def adb_dumpsys(params):
        service = params["service"]
        if service not in ALLOWED_SERVICES:
            return json.dumps(
                {
                    "error": f"Service '{service}' not allowed. Choose from: {sorted(ALLOWED_SERVICES)}",
                }
            )

        grep_pattern = params.get("grep_pattern", None)
        max_lines = min(params.get("max_lines", 500), 2000)

        rc, stdout, stderr = _run_adb("shell", "dumpsys", service)
        if rc != 0:
            return json.dumps(
                {"error": stderr or f"dumpsys {service} failed", "returncode": rc}
            )

        lines, truncated = _filter_lines(stdout, grep_pattern, max_lines)
        return json.dumps(
            {
                "service": service,
                "line_count": len(lines),
                "truncated": truncated,
                "content": "\n".join(lines),
            }
        )

    tools["adb_dumpsys"] = (
        {
            "name": "adb_dumpsys",
            "description": "Dump a specific Android system service. Use for detailed telephony/radio state inspection.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "service": {
                        "type": "string",
                        "enum": sorted(ALLOWED_SERVICES),
                        "description": "Android service to dump",
                    },
                    "grep_pattern": {
                        "type": "string",
                        "description": "Optional regex to filter output lines (case-insensitive)",
                    },
                    "max_lines": {
                        "type": "integer",
                        "description": "Max lines to return (default 500, max 2000)",
                    },
                },
                "required": ["service"],
            },
        },
        adb_dumpsys,
    )

    # --- adb_modem_health ---
    def adb_modem_health(params):
        wait_for_recovery = params.get("wait_for_recovery", False)
        poll_timeout = min(params.get("poll_timeout", 60), 120)

        def _check():
            rc_bb, bb_out, _ = _run_adb("shell", "getprop", "gsm.version.baseband")
            rc_sim, sim_out, _ = _run_adb("shell", "getprop", "gsm.sim.state")
            baseband = bb_out.strip() if rc_bb == 0 else ""
            sim = sim_out.strip() if rc_sim == 0 else ""
            alive = bool(baseband and baseband.lower() not in ("", "unknown"))
            return {
                "modem_alive": alive,
                "baseband_version": baseband,
                "sim_state": sim,
            }

        result = _check()

        if wait_for_recovery and not result["modem_alive"]:
            start = time.time()
            while time.time() - start < poll_timeout:
                time.sleep(3)
                result = _check()
                if result["modem_alive"]:
                    result["recovery_time_seconds"] = round(time.time() - start, 1)
                    break
            else:
                result["recovery_timed_out"] = True
                result["poll_timeout"] = poll_timeout

        return json.dumps(result, indent=2)

    tools["adb_modem_health"] = (
        {
            "name": "adb_modem_health",
            "description": "Quick modem alive check. Returns baseband version and SIM state. Optionally polls up to poll_timeout seconds waiting for modem recovery after a crash.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "wait_for_recovery": {
                        "type": "boolean",
                        "description": "If true and modem is down, poll until it recovers or timeout (default false)",
                    },
                    "poll_timeout": {
                        "type": "integer",
                        "description": "Max seconds to wait for recovery (default 60, max 120)",
                    },
                },
                "required": [],
            },
        },
        adb_modem_health,
    )

    return tools
