"""Pre-flight check that streaming to the master is set up and reachable.

Policy B: a worker that *looks* like it should be streaming but isn't will
fail at startup (second 1) instead of silently producing local-only data
that nobody sees on the dashboard until hour N.

Resolution order:

    1. AGENT_NO_SYNC=1                 → return immediately. Master / dev /
                                         CI runs use this to opt out.
    2. ~/.agentic-fuzz-sync.env absent → exit 2 with setup instructions.
    3. required keys missing           → exit 2. Required keys are
                                         AGENT_MASTER, AGENT_MASTER_PATH,
                                         AGENT_HOST_ID, AGENT_LOCAL_PATH
                                         (rsync blob path) and
                                         AGENT_INGEST_URL,
                                         AGENT_INGEST_TOKEN (Postgres
                                         ingest API).
    4. ssh -BatchMode probe to AGENT_MASTER fails → exit 2 with ssh stderr.
    5. HTTP GET ${AGENT_INGEST_URL}/healthz fails → exit 2 with the error.

Called by `run_agent.py` and `sweep_scripts_202604/sweep.py` right after
argparse so `--help` still works without ssh / network.
"""

import os
import shutil
import subprocess
import sys
import urllib.error
import urllib.request

ENV_FILE = os.path.expanduser("~/.agentic-fuzz-sync.env")
OPT_OUT_VAR = "AGENT_NO_SYNC"
SETUP_HINT = (
    f"Set {OPT_OUT_VAR}=1 to run local-only (the common case), or provide "
    f"a {ENV_FILE} file with the keys below to stream runs to a dashboard "
    "host."
)
REQUIRED_KEYS = (
    "AGENT_MASTER",
    "AGENT_MASTER_PATH",
    "AGENT_HOST_ID",
    "AGENT_LOCAL_PATH",
    "AGENT_INGEST_URL",
    "AGENT_INGEST_TOKEN",
)
HEALTHZ_TIMEOUT = 5.0


def _parse_env_file(path):
    out = {}
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def check_streaming_or_exit(logger=None):
    """Verify worker streaming setup, or exit(2) with a clear message.

    Returns silently on success or when the user has explicitly opted out.
    """

    def _say(msg, level="error"):
        if logger is not None:
            getattr(logger, level)(msg)
        else:
            print(msg, file=sys.stderr)

    if os.environ.get(OPT_OUT_VAR) == "1":
        _say(f"{OPT_OUT_VAR}=1 set — skipping streaming preflight.", "info")
        return

    if not os.path.exists(ENV_FILE):
        _say(f"Streaming preflight FAILED: {ENV_FILE} not found.\n  {SETUP_HINT}")
        sys.exit(2)

    cfg = _parse_env_file(ENV_FILE)
    missing = [k for k in REQUIRED_KEYS if not cfg.get(k)]
    if missing:
        _say(
            f"Streaming preflight FAILED: {ENV_FILE} missing keys: "
            f"{', '.join(missing)}.\n  {SETUP_HINT}"
        )
        sys.exit(2)

    if shutil.which("ssh") is None:
        _say("Streaming preflight FAILED: ssh not on PATH.")
        sys.exit(2)

    master = cfg["AGENT_MASTER"]
    probe = subprocess.run(
        [
            "ssh",
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "StrictHostKeyChecking=accept-new",
            master,
            "true",
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if probe.returncode != 0:
        _say(
            f"Streaming preflight FAILED: ssh {master} returned "
            f"{probe.returncode}.\n"
            f"  stderr: {probe.stderr.strip()}\n  {SETUP_HINT}"
        )
        sys.exit(2)

    ingest_url = cfg["AGENT_INGEST_URL"].rstrip("/")
    healthz = ingest_url + "/healthz"
    try:
        status, body = _probe_healthz(healthz)
    except Exception as e:
        _say(
            f"Streaming preflight FAILED: GET {healthz} raised "
            f"{type(e).__name__}: {e}.\n  {SETUP_HINT}"
        )
        sys.exit(2)
    if status != 200:
        _say(
            f"Streaming preflight FAILED: GET {healthz} returned "
            f"HTTP {status}: {body[:200]!r}.\n  {SETUP_HINT}"
        )
        sys.exit(2)

    _say(
        f"Streaming preflight OK ({master}, host_id={cfg['AGENT_HOST_ID']}, "
        f"ingest={ingest_url}).",
        "info",
    )


def _probe_healthz(url, timeout=HEALTHZ_TIMEOUT):
    """HTTP GET <url>; return (status_code, body_excerpt). Raises on transport error.

    The ingest /healthz endpoint is unauthenticated by design; this probe
    intentionally does not send the bearer token so a missing token still
    surfaces as a 401 from /ingest/healthz when callers need a deeper check.
    """
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read(512).decode("utf-8", "replace")
        return resp.status, body


def trigger_master_deploy_or_exit(logger=None, *, agent_path=None):
    """End-of-run hook used by run_agent.py and sweep.py.

    No-op stub — the static-snapshot Cloudflare Pages deploy was retired
    when the master moved to a Postgres-backed live dashboard. The
    function signature, call sites, and test imports are preserved so
    the cleanup PR can drop them in one coordinated change.
    """

    def _say(msg, level):
        if logger is not None:
            getattr(logger, level)(msg)
        else:
            print(msg, file=sys.stderr if level == "error" else sys.stdout)

    _say("trigger_master_deploy: no-op (live DB-backed dashboard).", "info")
    # `agent_path` retained for signature compatibility with existing callers.
    _ = agent_path


def _check_dashboard_ingest(protocol, device, logger=None):
    """Validate that we can successfully POST and DELETE data on the ingest API.

    Ensures full write-through pipeline verification without leaving test data
    behind in the database. Skipped if AGENT_NO_SYNC=1.
    """
    import json
    import time
    import uuid

    def _say(msg, level="error"):
        if logger is not None:
            getattr(logger, level)(msg)
        else:
            print(msg, file=sys.stderr if level in ("error", "critical", "warning") else sys.stdout)

    if os.environ.get(OPT_OUT_VAR) == "1":
        return

    _say("Running Dashboard Ingest & Delete preflight check...", "info")
    cfg = _parse_env_file(ENV_FILE)
    ingest_url = cfg["AGENT_INGEST_URL"].rstrip("/")
    token = cfg["AGENT_INGEST_TOKEN"]
    host_id = cfg.get("AGENT_HOST_ID")

    # Generate a temporary test run ID to avoid colliding with actual campaigns.
    # Must be exactly 8 lowercase hex characters; we prefix it with 'f000' for identification.
    test_run_id = "f000" + uuid.uuid4().hex[:4]


    # POST to check that the server is alive and successfully ingesting data
    post_url = f"{ingest_url}/ingest/runs"
    run_start_payload = {
        "run_id": test_run_id,
        "host_id": host_id,
        "session_id": "test-session-preflight",
        "device": device,
        "protocol": protocol,
        "timestamp": time.strftime("%Y%m%d-%H%M%S")
    }

    try:
        req = urllib.request.Request(
            post_url,
            method="POST",
            data=json.dumps(run_start_payload).encode("utf-8"),
            headers={
                "Authorization": f"Bearer {token}",
                "Content-Type": "application/json"
            }
        )
        with urllib.request.urlopen(req, timeout=HEALTHZ_TIMEOUT) as resp:
            if resp.status not in (200, 201):
                _say(f"Dashboard Ingest preflight FAILED: POST {post_url} returned HTTP {resp.status}")
                sys.exit(2)
    except Exception as e:
        _say(f"Dashboard Ingest preflight FAILED: POST {post_url} raised {type(e).__name__}: {e}")
        sys.exit(2)

    # DELETE to clean up the test run so the DB stays clean
    delete_url = f"{ingest_url}/ingest/runs/{test_run_id}"
    try:
        req = urllib.request.Request(
            delete_url,
            method="DELETE",
            headers={
                "Authorization": f"Bearer {token}"
            }
        )
        with urllib.request.urlopen(req, timeout=HEALTHZ_TIMEOUT) as resp:
            if resp.status not in (200, 204):
                _say(f"Dashboard Delete preflight FAILED: DELETE {delete_url} returned HTTP {resp.status}")
                sys.exit(2)
    except Exception as e:
        _say(f"Dashboard Delete preflight FAILED: DELETE {delete_url} raised {type(e).__name__}: {e}")
        sys.exit(2)

    _say("Dashboard Ingest & Delete preflight check OK.", "info")


def _check_llm_api(model=None, logger=None):
    """Verify that the LLM API endpoint is working and the credentials/model are valid.

    Sends a minimal prompt to the resolved model and verifies a successful completion.
    Gracefully catches and reports specific API errors (such as 429 rate limits or
    invalid API keys).
    """
    def _say(msg, level="error"):
        if logger is not None:
            getattr(logger, level)(msg)
        else:
            print(msg, file=sys.stderr if level in ("error", "critical", "warning") else sys.stdout)

    _say("Running LLM API connection preflight check...", "info")
    try:
        from constants import LLM_API_KEY, LLM_BASE_URL, MODEL as DEFAULT_MODEL
        from openai import OpenAI
    except Exception as e:
        _say(f"LLM preflight FAILED: Failed to import LLM config: {e}")
        sys.exit(2)

    resolved_model = model or DEFAULT_MODEL
    if not LLM_API_KEY:
        _say("LLM preflight FAILED: LLM_API_KEY is not set.")
        sys.exit(2)

    try:
        client = OpenAI(api_key=LLM_API_KEY, base_url=LLM_BASE_URL)
        # Verify liveness by requesting a minimal completion (max 5 tokens)
        client.chat.completions.create(
            model=resolved_model,
            messages=[{"role": "user", "content": "ping"}],
            max_tokens=5
        )
    except Exception as e:
        # Check if the exception contains an HTTP status code (e.g. 401, 429, 500)
        status_code = getattr(e, "status_code", "Unknown")
        _say(
            f"LLM preflight FAILED: Chat completion request failed for model '{resolved_model}' "
            f"on {LLM_BASE_URL} (Status Code: {status_code}) — {type(e).__name__}: {e}"
        )
        sys.exit(2)

    _say("LLM API preflight check OK.", "info")


def _check_sdr_connected(logger=None):
    """Verify that a USRP/SDR device is connected and detectable.

    Runs `uhd_find_devices` and parses the output to check for device presence.
    Required for 5G OTA fuzzing campaigns.
    """
    def _say(msg, level="error"):
        if logger is not None:
            getattr(logger, level)(msg)
        else:
            print(msg, file=sys.stderr if level in ("error", "critical", "warning") else sys.stdout)

    _say("Running SDR preflight check...", "info")
    uhd_find = shutil.which("uhd_find_devices")
    if uhd_find is None:
        _say("SDR preflight FAILED: uhd_find_devices not found on PATH.")
        sys.exit(2)
    try:
        res = subprocess.run([uhd_find], capture_output=True, text=True, timeout=10)
        if res.returncode != 0:
            _say(f"SDR preflight FAILED: uhd_find_devices returned {res.returncode}.\n  stderr: {res.stderr.strip()}")
            sys.exit(2)
        if "-- UHD Device" not in res.stdout:
            _say(f"SDR preflight FAILED: No UHD/SDR devices detected by uhd_find_devices.\n  stdout: {res.stdout.strip()}")
            sys.exit(2)
    except subprocess.TimeoutExpired:
        _say("SDR preflight FAILED: uhd_find_devices timed out after 10 seconds.")
        sys.exit(2)
    except Exception as e:
        _say(f"SDR preflight FAILED: uhd_find_devices execution raised {type(e).__name__}: {e}")
        sys.exit(2)

    _say("SDR preflight check OK.", "info")


def _check_adb_device(adb_serial, logger=None):
    """Verify that the target Android phone is connected and online via ADB.

    Checks device status using `adb -s <serial> get-state`.
    """
    def _say(msg, level="error"):
        if logger is not None:
            getattr(logger, level)(msg)
        else:
            print(msg, file=sys.stderr if level in ("error", "critical", "warning") else sys.stdout)

    _say(f"Running ADB device preflight check for serial '{adb_serial}'...", "info")
    from constants import ADB_PATH
    if not os.path.exists(ADB_PATH):
        _say(f"ADB preflight FAILED: ADB binary not found at '{ADB_PATH}'.")
        sys.exit(2)
    try:
        res = subprocess.run([ADB_PATH, "-s", adb_serial, "get-state"], capture_output=True, text=True, timeout=10)
        if res.returncode != 0:
            devs = subprocess.run([ADB_PATH, "devices"], capture_output=True, text=True, timeout=5)
            _say(
                f"ADB preflight FAILED: adb get-state for device '{adb_serial}' failed (exit code {res.returncode}).\n"
                f"  stderr: {res.stderr.strip()}\n"
                f"  stdout: {res.stdout.strip()}\n"
                f"  adb devices output:\n{devs.stdout.strip()}"
            )
            sys.exit(2)
        state = res.stdout.strip()
        if state != "device":
            _say(f"ADB preflight FAILED: Device '{adb_serial}' state is '{state}' (expected 'device').")
            sys.exit(2)
    except subprocess.TimeoutExpired:
        _say("ADB preflight FAILED: adb get-state timed out after 10 seconds.")
        sys.exit(2)
    except Exception as e:
        _say(f"ADB preflight FAILED: Failed to run adb command: {e}")
        sys.exit(2)

    _say("ADB device preflight check OK.", "info")


def _check_bt_serial_ports(host_port, target_port, logger=None):
    """Verify host port and target port are connected and accessible with appropriate read/write permissions."""
    def _say(msg, level="error"):
        if logger is not None:
            getattr(logger, level)(msg)
        else:
            print(msg, file=sys.stderr if level in ("error", "critical", "warning") else sys.stdout)

    _say(f"Running Bluetooth serial ports preflight check (host: {host_port}, target: {target_port})...", "info")
    if not host_port:
        _say("Bluetooth preflight FAILED: host_port is not specified.")
        sys.exit(2)
    if not target_port:
        _say("Bluetooth preflight FAILED: target_port is not specified.")
        sys.exit(2)

    # Host port verification
    if not os.path.exists(host_port):
        _say(f"Bluetooth preflight FAILED: Host port '{host_port}' does not exist.")
        sys.exit(2)
    if not os.access(host_port, os.R_OK | os.W_OK):
        _say(f"Bluetooth preflight FAILED: Host port '{host_port}' is not readable/writable (permission denied).")
        sys.exit(2)

    # Target port verification
    if not os.path.exists(target_port):
        _say(f"Bluetooth preflight FAILED: Target port '{target_port}' does not exist.")
        sys.exit(2)
    if not os.access(target_port, os.R_OK | os.W_OK):
        _say(f"Bluetooth preflight FAILED: Target port '{target_port}' is not readable/writable (permission denied).")
        sys.exit(2)

    _say("Bluetooth serial ports preflight check OK.", "info")


def run_preflight_checks(
    protocol,
    device,
    model=None,
    host_port="/dev/ttyUSB1",
    target_port="/dev/ttyUSB2",
    adb_serial=None,
    logger=None,
):
    """Run all preflight checks for the worker in sequence.

    Fails fast (exits with status code 2) at the first failure point.
    """
    def _say(msg, level="error"):
        if logger is not None:
            getattr(logger, level)(msg)
        else:
            print(msg, file=sys.stderr if level in ("error", "critical", "warning") else sys.stdout)

    # 1. Basic streaming connection/auth checks
    _say("Running basic streaming preflight check...", "info")
    check_streaming_or_exit(logger)

    # 2. Deep Dashboard Ingest & Delete check
    _check_dashboard_ingest(protocol, device, logger)

    # 3. LLM API connection check
    _check_llm_api(model, logger)

    # 4. Hardware connectivity checks
    if protocol == "fiveg":
        # SDR is required for 5G campaigns
        _check_sdr_connected(logger)
        # ADB device check is only performed if an adb_serial is configured in the profile
        if adb_serial:
            _check_adb_device(adb_serial, logger)
    elif protocol == "bt":
        # BT campaigns require host and target serial ports to be connected and accessible
        _check_bt_serial_ports(host_port, target_port, logger)


