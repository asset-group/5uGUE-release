#!/usr/bin/env python3
"""Entry point for the agentic 5G NR protocol fuzzer."""

import argparse
import json
import logging
import os
import sys
import time
import uuid

# Bootstrap sys.path from this file's location (no hardcoded paths)
_AGENT_PATH = os.path.dirname(os.path.abspath(__file__))
_WDISSECTOR_PATH = os.path.dirname(os.path.dirname(_AGENT_PATH))

# Our module first so our constants.py is found
sys.path.insert(0, _AGENT_PATH)
# WDissector C extension (_wdissector.so) lives in bin/
sys.path.insert(1, os.path.join(_WDISSECTOR_PATH, "bin"))

# WDissector needs to run from its root directory
os.chdir(_WDISSECTOR_PATH)

from constants import AGENT_PATH, WDISSECTOR_PATH  # noqa: E402
from upstream.utils.misc import setup_logging

_app_log_file = setup_logging("DEBUG")
logger = logging.getLogger(__name__)

from constants import KB_PATH, LOG_PATH, RUNTIME_LOG_PATH

# Add runtime log file handler (initial name; renamed after run_id is generated)
_log_fmt = logging.Formatter(
    "%(asctime)s [%(levelname)s] %(filename)s:%(lineno)d: %(message)s"
)
_initial_ts = time.strftime("%Y%m%d_%H%M%S")
_runtime_log_file = os.path.join(RUNTIME_LOG_PATH, f"run_{_initial_ts}.log")
_runtime_handler = logging.FileHandler(_runtime_log_file)
_runtime_handler.setLevel(logging.DEBUG)
_runtime_handler.setFormatter(_log_fmt)
logging.getLogger().addHandler(_runtime_handler)

logger.info(f"App log: {_app_log_file}")
logger.info(f"Runtime log: {_runtime_log_file}")


def parse_args():
    parser = argparse.ArgumentParser(description="Agentic 5G NR protocol fuzzer")
    parser.add_argument(
        "--max-turns",
        type=int,
        default=100,
        help="Maximum number of agent turns (0 = unlimited, default: 100)",
    )
    parser.add_argument(
        "--cold-start",
        action="store_true",
        help="Ignore static known_crashes.json and global KB; start from web research only",
    )
    from device_profile import get_active_device

    _default_device, _default_protocol = get_active_device()
    parser.add_argument(
        "--protocol",
        type=str,
        required=True,
        choices=["fiveg", "bt", "wifi"],
        help="Protocol to fuzz (fiveg, bt, wifi)",
    )
    parser.add_argument(
        "--device",
        type=str,
        default=_default_device,
        help=(
            "Device profile ID to use (default: from data/active_device.json). "
            "See data/devices/ for available profiles."
        ),
    )
    parser.add_argument(
        "--model",
        type=str,
        default=None,
        help="LLM model ID override (e.g. google/gemini-3.1-pro-preview, anthropic/claude-sonnet-4.6)",
    )
    parser.add_argument(
        "--version",
        type=str,
        default="full",
        choices=["v1", "v2", "v3", "v3f", "full"],
        help="Experiment version: v1 (no knowledge/research), v2 (local papers), v3 (full research), v3f (filtered research, no papers, domain-restricted web), full (default)",
    )
    parser.add_argument(
        "--hub-loc",
        type=str,
        default="1-3",
        help="USB hub location for uhubctl (default: 1-3)",
    )
    parser.add_argument(
        "--hub-port",
        type=int,
        default=1,
        help="USB hub port for uhubctl (default: 1)",
    )
    parser.add_argument(
        "--host-port",
        type=str,
        default="/dev/ttyUSB1",
        help="Host adapter serial port (Bluetooth ESP32, default: /dev/ttyUSB1)",
    )
    parser.add_argument(
        "--target-port",
        type=str,
        default="/dev/ttyUSB2",
        help="Target board serial port (Bluetooth ESP32, default: /dev/ttyUSB2)",
    )
    args = parser.parse_args()

    return args


def main():
    args = parse_args()

    # Load device profile
    from device_profile import (
        get_device_utils,
        get_exploiter,
        load_device_profile,
        patch_device_configs,
    )

    profile = load_device_profile(args.device, args.protocol)
    if profile.protocol != args.protocol:
        raise ValueError(
            f"Protocol mismatch: CLI specified protocol '{args.protocol}' "
            f"but device '{args.device}' profile specifies protocol '{profile.protocol}'."
        )

    # Fail fast if worker preflight checks fail.
    # Set AGENT_NO_SYNC=1 to opt out of streaming checks (master / dev / CI runs).
    from sync_preflight import run_preflight_checks

    run_preflight_checks(
        protocol=args.protocol,
        device=args.device,
        model=args.model,
        host_port=args.host_port,
        target_port=args.target_port,
        adb_serial=getattr(profile, "adb_serial", None),
        logger=logger,
    )


    # Set active session context for client-side ingest validation
    from ingest_client import set_active_session_context

    set_active_session_context(protocol=args.protocol, device=args.device)

    logger.info(
        f"Device: {args.device} | protocol: {args.protocol} "
        f"| vendor: {profile.vendor} | device: {profile.device}"
    )

    # Patch WDissector configs for this device
    patch_device_configs(profile, log=logger)

    # Build version config
    from version_config import FuzzerVersion, get_version_config

    version_config = get_version_config(args.version)
    logger.info(f"Version: {args.version} | config: {version_config}")

    # ── Generate run_id + shared timestamp early ──
    run_id = uuid.uuid4().hex[:8]
    _shared_ts = time.strftime("%Y%m%d-%H%M%S")
    _ts_for_file = _shared_ts.replace("-", "_", 1)  # 20260316_152200
    logger.info(f"Run ID: {run_id}")

    # Compute session_id using the shared timestamp — run_id prefixed
    if version_config.version != FuzzerVersion.FULL:
        session_id = f"{run_id}-rq1-{args.version}-{_shared_ts}"
    elif args.cold_start:
        session_id = f"{run_id}-coldstart-{_shared_ts}"
    else:
        env_session = os.environ.get("SESSION_ID", "")
        session_id = f"{run_id}-{env_session}" if env_session else run_id

    # Rename log files to include run_id prefix
    new_app_log = os.path.join(LOG_PATH, f"{run_id}_app_{_ts_for_file}.log")
    os.rename(_app_log_file, new_app_log)
    # Update the file handler on root logger
    for handler in logging.getLogger().handlers:
        if isinstance(handler, logging.FileHandler) and hasattr(
            handler, "baseFilename"
        ):
            if os.path.abspath(handler.baseFilename) == os.path.abspath(_app_log_file):
                handler.close()
                handler.baseFilename = os.path.abspath(new_app_log)
                handler.stream = handler._open()
                break
    logger.info(f"Renamed app log: {new_app_log}")

    new_runtime_log = os.path.join(RUNTIME_LOG_PATH, f"{run_id}_run_{_ts_for_file}.log")
    os.rename(_runtime_log_file, new_runtime_log)
    _runtime_handler.close()
    _runtime_handler.baseFilename = os.path.abspath(new_runtime_log)
    _runtime_handler.stream = _runtime_handler._open()
    logger.info(f"Renamed runtime log: {new_runtime_log}")

    # Write manifest
    # TODO: why the name is so strange? DEFAULT is DEFAULT
    from constants import MODEL as _DEFAULT_MODEL

    manifest = {
        "run_id": run_id,
        "session_id": session_id,
        "timestamp": _shared_ts,
        "model": args.model or _DEFAULT_MODEL,
        "version": args.version,
        "device": args.device,
        "protocol": args.protocol,
        "app_log": new_app_log,
        "runtime_log": new_runtime_log,
        "metrics": os.path.join(RUNTIME_LOG_PATH, f"agent_metrics_{run_id}.jsonl"),
        "resources": os.path.join(RUNTIME_LOG_PATH, f"resources_{run_id}.jsonl"),
        "kb_dir": os.path.join(KB_PATH, session_id),
    }
    _manifest_path = os.path.join(RUNTIME_LOG_PATH, f"{run_id}_manifest.json")
    with open(_manifest_path, "w") as f:
        json.dump(manifest, f, indent=2)
    logger.info(f"Manifest: {_manifest_path}")

    try:
        from constants import HOST_ID
        from ingest_client import enqueue

        enqueue(
            "run_start",
            {
                "run_id": run_id,
                "host_id": HOST_ID,
                "session_id": session_id,
                "device": args.device,
                "protocol": args.protocol,
                "version": args.version,
                "model": args.model or _DEFAULT_MODEL,
                "max_turns": args.max_turns,
                "timestamp": _shared_ts,
                "app_log_path": new_app_log,
                "runtime_log_path": new_runtime_log,
                "metrics_png_path": os.path.join(
                    RUNTIME_LOG_PATH, f"agent_metrics_{run_id}.png"
                ),
                "resource_metrics_png_path": os.path.join(
                    RUNTIME_LOG_PATH, f"resources_{run_id}.png"
                ),
            },
            run_id=run_id,
        )
    except Exception as e:
        logger.warning(f"ingest enqueue failed (run_start): {e}")

    # Validate API key
    from constants import LLM_API_KEY, LLM_BASE_URL, LLM_PROVIDER

    if not LLM_API_KEY:
        print(f"ERROR: No API key set for LLM_PROVIDER={LLM_PROVIDER}.")
        print(
            "Set OPENROUTER_API_KEY (provider=openrouter) or AZURE_API_KEY (provider=azure)"
        )
        print("Select provider via LLM_PROVIDER=openrouter|azure (default: openrouter)")
        print("Optionally set MODEL (default: anthropic/claude-sonnet-4.6)")
        sys.exit(1)
    logger.info(f"Using LLM backend ({LLM_PROVIDER}): {LLM_BASE_URL}")

    # Ensure profile log subdirectory exists
    os.makedirs(profile.log_subdir_path, exist_ok=True)

    # Initialize WDissector tool
    logger.info("Initializing WDissector...")
    from upstream.utils.wd_utils import WDissectorTool

    if profile.protocol == "bt":
        wd_tool = WDissectorTool(profile.protocol, 4)
    else:
        wd_tool = WDissectorTool(profile.protocol, 0)

    logger.info("WDissector initialized successfully")

    # Initialize exploiter via device registry
    logger.info(f"Initializing exploiter for {args.device} ({args.protocol})...")
    exploiter = get_exploiter(
        args.device,
        args.protocol,
        profile,
        wd_tool,
        run_dir=WDISSECTOR_PATH,
        hub_loc=args.hub_loc,
        target_hub_port=args.hub_port,
        host_port=args.host_port,
        target_port=args.target_port,
    )

    # Initialize target device utils via device registry
    logger.info(f"Initializing device utils for {args.device} ({args.protocol})...")
    td_utils = get_device_utils(args.device, args.protocol, profile)

    # Base capture for initial briefing
    base_capture_path = profile.normal_capture

    # Generate base state machine
    logger.info("Generating base state machine...")
    from upstream.utils.state_transition import gen_sm

    base_sm = gen_sm(wd_tool, base_capture_path)
    logger.info(f"Base state machine: {len(base_sm.states)} states")

    # Initialize resource monitor
    from resource_monitor import ResourceMonitor

    resource_monitor = ResourceMonitor(run_id=run_id, log_dir=RUNTIME_LOG_PATH)
    resource_monitor.start()

    # Initialize agent metrics
    from agent_metrics import AgentMetrics

    agent_metrics = AgentMetrics(run_id=run_id, log_dir=RUNTIME_LOG_PATH)
    agent_metrics.start()

    # Initialize knowledge base
    from knowledge_base import KnowledgeBase

    kb = KnowledgeBase(
        session_id=session_id, enable_global_kb=version_config.load_global_kb
    )
    logger.info(f"Knowledge base: session={session_id}, {kb.test_count} prior tests")

    # Initialize execution engine — test IDs start from 0 each run, prefixed with run_id
    from execution_engine import ExecutionEngine

    engine = ExecutionEngine(
        exploiter,
        td_utils,
        wd_tool,
        base_sm,
        run_id=run_id,
        exploit_folder=profile.exploit_folder,
        capture_filename=profile.capture_filename,
        profile=profile,
    )

    # Build tool registry
    session_exploits = set()
    from tools import build_tool_registry

    tools = build_tool_registry(
        wd_tool,
        td_utils,
        engine,
        kb,
        config=version_config,
        session_exploits=session_exploits,
        profile=profile,
    )
    logger.info(f"Tool registry: {len(tools)} tools registered")
    for name in tools:
        logger.info(f"  - {name}")

    # Create and run agent
    from agent_core import FuzzAgent

    agent = FuzzAgent(
        tools,
        engine,
        kb,
        max_turns=args.max_turns,
        cold_start=args.cold_start,
        target_vendor=profile.vendor,
        target_protocol=profile.protocol,
        model_override=args.model,
        resource_monitor=resource_monitor,
        agent_metrics=agent_metrics,
        config=version_config,
        profile=profile,
    )

    logger.info("=" * 60)
    logger.info("Starting Agentic 5G NR Fuzzer")
    logger.info(f"Base capture: {base_capture_path}")
    logger.info(f"Session: {session_id}")
    logger.info("=" * 60)

    # Track the actual outcome so the run_finish PATCH reports it
    # truthfully. Default 'failed' covers any exception path that
    # doesn't reach a more specific arm — better to mark a run failed
    # than to silently call it 'completed' (the prior behaviour, which
    # made aborted/crashed runs indistinguishable on the dashboard).
    run_status = "failed"
    try:
        agent.run(base_capture_path)
        run_status = "completed"
    except KeyboardInterrupt:
        run_status = "aborted"
        logger.info(
            "Agent stopped by user (Ctrl-C) — run will be marked status='aborted'"
        )
    except Exception as e:
        logger.critical(f"Agent crashed: {e}", exc_info=True)
    finally:
        logger.info(f"Total tests: {engine.test_count}")
        logger.info(
            f"Total tokens - in: {agent.total_input_tokens}, out: {agent.total_output_tokens}"
        )
        resource_monitor.stop()
        logger.info(f"Resource chart: {resource_monitor._png_path}")
        agent_metrics.stop()
        logger.info(f"Agent metrics chart: {agent_metrics.png_path}")

        try:
            from ingest_client import enqueue

            last = agent_metrics._records[-1] if agent_metrics._records else {}
            enqueue(
                "run_finish",
                {
                    "ended_at": time.time(),
                    "status": run_status,
                    "final_total_crashes": last.get("cumulative_crashes", 0),
                    "final_unique_crashes": last.get("session_unique_crashes", 0),
                    "final_publicly_known": last.get("cumulative_publicly_known", 0),
                    "final_non_publicly_known": last.get(
                        "cumulative_non_publicly_known", 0
                    ),
                    "final_fully_novel": last.get("cumulative_fully_novel", 0),
                    "total_input_tokens": agent.total_input_tokens,
                    "total_output_tokens": agent.total_output_tokens,
                },
                run_id=run_id,
            )
            logger.info(f"Enqueued run_finish: status={run_status}")
        except Exception as e:
            logger.warning(f"ingest enqueue failed (run_finish): {e}")

        # Final flush + Cloudflare deploy on the master. Workers no longer
        # need Cloudflare creds — those live in ~/.agentic-fuzz-master.env
        # on the server. Skipped when AGENT_NO_SYNC=1; otherwise a non-zero
        # exit from the trigger fails the run so silent stale-dashboard
        # bugs surface immediately.
        from sync_preflight import trigger_master_deploy_or_exit

        trigger_master_deploy_or_exit(logger, agent_path=_AGENT_PATH)


if __name__ == "__main__":
    main()
