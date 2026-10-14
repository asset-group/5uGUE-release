"""Device profile system: loads device-specific configuration for any target device type.

Supported device types: "modem", "bluetooth" (and "wifi" in future).

Layout:
    data/devices/<device_type>/<device_id>/profile.json

Each profile.json must contain a "device_type" field plus all fields
required by the corresponding subclass (see BASE_REQUIRED_FIELDS,
MODEM_REQUIRED_FIELDS, BT_REQUIRED_FIELDS).

Usage:
    from device_profile import load_device_profile, get_active_device

    device_id, device_type = get_active_device()
    profile = load_device_profile(device_id, device_type)
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from typing import Literal

logger = logging.getLogger(__name__)

# ── Path constants ──────────────────────────────────────────────────────────

_AGENT_PATH = os.path.dirname(os.path.abspath(__file__))
_WDISSECTOR_PATH = os.path.dirname(os.path.dirname(_AGENT_PATH))
_DEVICES_PATH = os.path.join(_AGENT_PATH, "data", "devices")
_ACTIVE_DEVICE_PATH = os.path.join(_AGENT_PATH, "data", "active_device.json")

# Host-scoped runtime log path — pulled from constants so HOST_ID validation
# happens in one place. Falls back gracefully in tests that skip secret_keys.
try:
    from constants import RUNTIME_LOG_PATH as _RUNTIME_LOG_PATH
except Exception:
    _RUNTIME_LOG_PATH = os.path.join(_AGENT_PATH, "runtime_logs")

# ── Default ADB magic words for modem crash detection ──────────────────────

DEFAULT_ADB_MAGIC_WORDS: list[str] = [
    "ModemEvent: modem_failure",
    "ModemRestartStats",
    "SOC crashed",
    "Unable to wake SOC",
]

# ── Required profile fields ─────────────────────────────────────────────────

# Fields every device protocol must supply in profile.json.
BASE_REQUIRED_FIELDS: list[str] = [
    "vendor",
    "device",
    "protocol",
    "header_offset",
    "capture_filename",
    "exploit_prefix",
    "exploit_folder_name",
    "log_subdir",
    "crash_oracle",
    "role_description",
    "web_search_examples",
]

# Additional fields required for 5G profiles.
FIVEG_REQUIRED_FIELDS: list[str] = BASE_REQUIRED_FIELDS + [
    "adb_serial",
    "adb_grep_hints",
]

# Additional fields required for Bluetooth profiles.
BT_REQUIRED_FIELDS: list[str] = BASE_REQUIRED_FIELDS + [
    "target_address",
]

# Map each protocol string to its required-fields list.
_REQUIRED_FIELDS_BY_PROTOCOL: dict[str, list[str]] = {
    "fiveg": FIVEG_REQUIRED_FIELDS,
    "bt": BT_REQUIRED_FIELDS,
}

ProtocolType = Literal["fiveg", "bt", "wifi"]


# ── Profile dataclasses ─────────────────────────────────────────────────────


@dataclass
class DeviceProfile:
    """Base profile shared by all device types.

    Every field here is available on both FivegProfile and BtProfile
    without any isinstance checks.
    """

    # --- Identity (from profile.json) ---
    vendor: str
    device: str
    protocol: str

    # --- WDissector configuration (shared across all WDissector-based devices) ---
    header_offset: int
    capture_filename: str
    exploit_prefix: str
    exploit_folder_name: str
    log_subdir: str
    crash_oracle: dict  # structure varies by device type, but always a dict

    # --- Agent prompting (from profile.json) ---
    role_description: str
    web_search_examples: list[str]

    # --- Resolved paths (computed by loader) ---
    profile_dir: str
    known_crashes_path: str
    crash_signatures_path: str
    normal_capture: str
    fuzz_capture: str
    exploit_folder: str
    log_subdir_path: str

    # --- Loaded markdown content (optional files in profile_dir) ---
    prompt_crash_knowledge: str  # content of prompt_crash_knowledge.md, or ""
    prompt_strategy_hints: str  # content of prompt_strategy_hints.md, or ""
    prompt_research_hints: str  # content of prompt_research_hints.md, or ""


@dataclass
class FivegProfile(DeviceProfile):
    """Profile for 5G/LTE modem targets.

    Extends DeviceProfile with ADB-specific fields used by modem exploiters
    and WDissector ADB monitor integration.
    """

    adb_serial: str  # ADB device serial; empty string means ADB not used
    adb_grep_hints: list[str]  # logcat grep keywords for crash filtering


@dataclass
class BtProfile(DeviceProfile):
    """Profile for Bluetooth target devices.

    Extends DeviceProfile with Bluetooth-specific addressing fields.
    """

    target_address: str  # Target device Bluetooth MAC address


# ── Internal helpers ────────────────────────────────────────────────────────


def _load_markdown(path: str) -> str:
    """Read and return a markdown file's content, or empty string if absent."""
    if os.path.isfile(path):
        with open(path) as f:
            return f.read()
    return ""


def _load_common_fields(profile_dir: str, data: dict) -> dict:
    """Compute and return the common keyword arguments for DeviceProfile.

    Resolves paths, loads markdown files, and computes derived paths.
    All returned values are ready to be unpacked into a DeviceProfile subclass.
    """
    known_crashes_path = os.path.join(profile_dir, "known_crashes.json")
    crash_signatures_path = os.path.join(profile_dir, "crash_signatures.json")

    prompt_crash_knowledge = _load_markdown(
        os.path.join(profile_dir, "prompt_crash_knowledge.md")
    )
    prompt_strategy_hints = _load_markdown(
        os.path.join(profile_dir, "prompt_strategy_hints.md")
    )
    prompt_research_hints = _load_markdown(
        os.path.join(profile_dir, "prompt_research_hints.md")
    )

    normal_capture = os.path.join(
        profile_dir, "captures", "normal", data["capture_filename"]
    )
    fuzz_capture = os.path.join(
        profile_dir, "captures", "fuzz", data["capture_filename"]
    )

    exploit_folder = os.path.join(
        _WDISSECTOR_PATH, "modules", "exploits", data["exploit_folder_name"]
    )
    log_subdir_path = os.path.join(_RUNTIME_LOG_PATH, data["log_subdir"])

    return dict(
        vendor=data["vendor"],
        device=data["device"],
        protocol=data["protocol"],
        header_offset=data["header_offset"],
        capture_filename=data["capture_filename"],
        exploit_prefix=data["exploit_prefix"],
        exploit_folder_name=data["exploit_folder_name"],
        log_subdir=data["log_subdir"],
        crash_oracle=data["crash_oracle"],
        role_description=data["role_description"],
        web_search_examples=data["web_search_examples"],
        profile_dir=profile_dir,
        known_crashes_path=known_crashes_path,
        crash_signatures_path=crash_signatures_path,
        normal_capture=normal_capture,
        fuzz_capture=fuzz_capture,
        exploit_folder=exploit_folder,
        log_subdir_path=log_subdir_path,
        prompt_crash_knowledge=prompt_crash_knowledge,
        prompt_strategy_hints=prompt_strategy_hints,
        prompt_research_hints=prompt_research_hints,
    )


def _build_fiveg_profile(profile_dir: str, data: dict) -> FivegProfile:
    return FivegProfile(
        **_load_common_fields(profile_dir, data),
        adb_serial=data["adb_serial"],
        adb_grep_hints=data["adb_grep_hints"],
    )


def _build_bt_profile(profile_dir: str, data: dict) -> BtProfile:
    return BtProfile(
        **_load_common_fields(profile_dir, data),
        target_address=data["target_address"],
    )


_PROFILE_BUILDERS: dict[str, object] = {
    "fiveg": _build_fiveg_profile,
    "bt": _build_bt_profile,
}


# ── Public API ──────────────────────────────────────────────────────────────


def load_device_profile(device: str, protocol: str) -> DeviceProfile:
    """Load a device profile from data/devices/<protocol>/<device>/profile.json.

    Validates that:
    - protocol is a supported protocol
    - The profile directory exists
    - profile.json is present and has all required fields for the protocol
    - The device has a DEVICE_REGISTRY entry

    Returns an instance of the appropriate DeviceProfile subclass.
    """
    if protocol not in _REQUIRED_FIELDS_BY_PROTOCOL:
        supported = sorted(_REQUIRED_FIELDS_BY_PROTOCOL.keys())
        raise ValueError(f"Unknown protocol '{protocol}'. Supported: {supported}")

    profile_dir = os.path.join(_DEVICES_PATH, protocol, device)
    if not os.path.isdir(profile_dir):
        available = list_available_devices(protocol)
        raise ValueError(
            f"Device profile '{device}' (protocol='{protocol}') not found at "
            f"{profile_dir}. Available {protocol} devices: {available}"
        )

    registry_key = (protocol, device)
    if registry_key not in DEVICE_REGISTRY:
        raise ValueError(
            f"Device '{device}' (protocol='{protocol}') has a profile directory "
            f"but no DEVICE_REGISTRY entry. Add an entry in device_profile.py "
            f"to support this device."
        )

    profile_json_path = os.path.join(profile_dir, "profile.json")
    if not os.path.isfile(profile_json_path):
        raise ValueError(f"Missing profile.json in {profile_dir}")

    with open(profile_json_path) as f:
        data = json.load(f)

    # Validate all required fields for this protocol.
    required = _REQUIRED_FIELDS_BY_PROTOCOL[protocol]
    missing = [field for field in required if field not in data]
    if missing:
        raise ValueError(
            f"profile.json for '{device}' (protocol='{protocol}') is missing "
            f"required fields: {missing}"
        )

    # Build the correct subclass.
    builder = _PROFILE_BUILDERS[protocol]
    profile = builder(profile_dir, data)  # type: ignore[operator]

    # Ensure the device field matches the folder name (which is the device ID used in the path).
    folder_name = os.path.basename(profile_dir)
    if protocol == "bt" and profile.device != folder_name:
        raise ValueError(
            f"Device field '{profile.device}' in profile.json does not match the "
            f"folder name '{folder_name}' in the path"
        )

    return profile


def list_available_devices(protocol: str | None = None) -> list[str]:
    """List all device profile directories under data/devices/.

    Args:
        protocol: If given, restrict to that protocol subdirectory.
                  If None, return all devices across all protocols as
                  "<protocol>/<device_id>" strings.

    Returns a sorted list of device IDs (if protocol given) or
    "<protocol>/<device_id>" strings (if protocol is None).
    """
    if protocol is not None:
        type_dir = os.path.join(_DEVICES_PATH, protocol)
        if not os.path.isdir(type_dir):
            return []
        return sorted(
            d
            for d in os.listdir(type_dir)
            if os.path.isdir(os.path.join(type_dir, d))
            and os.path.isfile(os.path.join(type_dir, d, "profile.json"))
        )
    # All types
    results: list[str] = []
    if not os.path.isdir(_DEVICES_PATH):
        return results
    for dtype in sorted(os.listdir(_DEVICES_PATH)):
        type_dir = os.path.join(_DEVICES_PATH, dtype)
        if not os.path.isdir(type_dir):
            continue
        for d in sorted(os.listdir(type_dir)):
            if os.path.isdir(os.path.join(type_dir, d)) and os.path.isfile(
                os.path.join(type_dir, d, "profile.json")
            ):
                results.append(f"{dtype}/{d}")
    return results


def get_active_device() -> tuple[str, str]:
    """Read the active device from data/active_device.json.

    Returns:
        (device_id, protocol) tuple.

    Falls back to ("mediatek", "fiveg") if the file is missing or malformed.
    """
    try:
        with open(_ACTIVE_DEVICE_PATH) as f:
            data = json.load(f)
        device = data.get("device", "mediatek")
        protocol = data.get("protocol", "fiveg")
        return device, protocol
    except (FileNotFoundError, json.JSONDecodeError, KeyError):
        return "mediatek", "fiveg"


# ── WDissector config patching ──────────────────────────────────────────────


def patch_device_configs(
    profile: DeviceProfile, log: logging.Logger | None = None
) -> None:
    """Patch WDissector config files to match the active device profile.

    Dispatches to the appropriate per-protocol patcher based on profile.protocol.
    """
    log = log or logger
    if profile.protocol == "fiveg":
        if not isinstance(profile, FivegProfile):
            raise TypeError(
                f"Expected FivegProfile for protocol='fiveg', got {type(profile)}"
            )
        _patch_modem_configs(profile, log)
    elif profile.protocol == "bt":
        if not isinstance(profile, BtProfile):
            raise TypeError(
                f"Expected BtProfile for protocol='bt', got {type(profile)}"
            )
        _patch_bluetooth_configs(profile, log)
    else:
        log.warning(
            f"patch_device_configs: no patcher implemented for "
            f"protocol='{profile.protocol}' — skipping config patch"
        )


def _patch_modem_configs(profile: FivegProfile, log: logging.Logger) -> None:
    """Patch WDissector 5G + global config files for the active modem.

    Writes:
      - 5gnr_gnb_config.json:
          Monitor.ActiveMonitorTypes  ← profile.crash_oracle.active_monitor_type
          Monitor.ADB.ADBDevice       ← profile.adb_serial
          Monitor.ADB.ADBMagicWords   ← profile.crash_oracle.adb_magic_words
                                        (or DEFAULT_ADB_MAGIC_WORDS)
      - global_config.json:
          Services.UEModemManager.EnableADB  ← bool(profile.adb_serial)
          Services.UEModemManager.ADBDevice  ← profile.adb_serial (when set)

    ADBMagicWords is always written (override or default) so switching modems
    reliably restores the correct list.
    """
    fiveg_paths = [
        os.path.join(_WDISSECTOR_PATH, "configs", "5gnr_gnb_config.json"),
        os.path.join(
            _WDISSECTOR_PATH, "bindings", "python", "configs", "5gnr_gnb_config.json"
        ),
    ]
    monitor_type = profile.crash_oracle.get("active_monitor_type")
    magic_words = profile.crash_oracle.get("adb_magic_words", DEFAULT_ADB_MAGIC_WORDS)

    try:
        from constants import ENABLE_LTE_BS
    except Exception:
        ENABLE_LTE_BS = False

    for p in fiveg_paths:
        if not os.path.isfile(p):
            continue
        with open(p) as f:
            cfg = json.load(f)
        changed = False
        if monitor_type is not None:
            cfg["config"]["Monitor"]["ActiveMonitorTypes"] = [monitor_type]
            changed = True
        if "ADB" in cfg["config"]["Monitor"]:
            if profile.adb_serial:
                cfg["config"]["Monitor"]["ADB"]["ADBDevice"] = profile.adb_serial
                changed = True
            cfg["config"]["Monitor"]["ADB"]["ADBMagicWords"] = magic_words
            changed = True
        if "NR5G" in cfg["config"]:
            cfg["config"]["NR5G"]["AutoStartCoreNetwork"] = not ENABLE_LTE_BS
            cfg["config"]["NR5G"]["AutoStartBaseStation"] = True
            changed = True
        if changed:
            with open(p, "w") as f:
                json.dump(cfg, f, indent=4)
            log.info(
                f"Patched Monitor (ActiveMonitorTypes=[{monitor_type}], "
                f"ADBDevice={profile.adb_serial}, ADBMagicWords={magic_words}, "
                f"AutoStartCoreNetwork={not ENABLE_LTE_BS}, AutoStartBaseStation=True) in {p}"
            )

    global_paths = [
        os.path.join(_WDISSECTOR_PATH, "configs", "global_config.json"),
        os.path.join(
            _WDISSECTOR_PATH, "bindings", "python", "configs", "global_config.json"
        ),
    ]
    enable_adb = bool(profile.adb_serial)
    for p in global_paths:
        if not os.path.isfile(p):
            continue
        with open(p) as f:
            cfg = json.load(f)
        cfg["config"]["Services"]["UEModemManager"]["EnableADB"] = enable_adb
        cfg["config"]["Services"]["UEModemManager"][
            "AutoReconnectModem"
        ] = not ENABLE_LTE_BS
        if profile.adb_serial:
            cfg["config"]["Services"]["UEModemManager"]["ADBDevice"] = (
                profile.adb_serial
            )
        with open(p, "w") as f:
            json.dump(cfg, f, indent=4)
        log.info(
            f"Patched EnableADB={enable_adb}, "
            f"AutoReconnectModem={not ENABLE_LTE_BS}, "
            f"ADBDevice={profile.adb_serial or '(unchanged)'} in {p}"
        )


def _patch_bluetooth_configs(profile: BtProfile, log: logging.Logger) -> None:
    """Patch WDissector Bluetooth config files for the active BT device.

    Writes:
      - bt_config.json:
          Bluetooth.TargetBDAddress    ← profile.target_address

    Also enforces mandatory Bluetooth config values that must always be set
    to specific values for correct fuzzer operation (regardless of device):
          Bluetooth.BridgeHCI          ← True  (required for HCI interception)
          Bluetooth.InterceptTX        ← True  (required to hold/modify TX packets)
          Bluetooth.LMPSniffing        ← True  (required for low-level LMP visibility)
          Bluetooth.RXBypassOnDemand   ← False (must be disabled)

    The following fields are intentionally left untouched (user-tunable):
          Bluetooth.DisableRoleSwitch  (can be True or False per exploit strategy)
          Bluetooth.RXBypass           (can be True for flooding exploits)
    """
    # Mandatory values that must always be enforced.
    _REQUIRED_BT_VALUES: dict[str, bool] = {
        "BridgeHCI": True,
        "InterceptTX": True,
        "LMPSniffing": True,
        "RXBypassOnDemand": False,
    }

    try:
        from constants import BT_WD_SM_CONFIG
    except Exception:
        BT_WD_SM_CONFIG = os.path.join(_WDISSECTOR_PATH, "configs", "bt_config.json")

    bt_paths = [
        BT_WD_SM_CONFIG,
        os.path.join(
            _WDISSECTOR_PATH, "bindings", "python", "configs", "bt_config.json"
        ),
    ]
    for p in bt_paths:
        if not os.path.isfile(p):
            log.debug(f"BT config not found (skipping): {p}")
            continue
        with open(p) as f:
            cfg = json.load(f)
        changed = False
        bt_section = cfg.get("config", {}).get("Bluetooth", {})

        # Patch target device address if the key exists in the config.
        if "TargetBDAddress" in bt_section and profile.target_address:
            bt_section["TargetBDAddress"] = profile.target_address
            changed = True

        # Enforce mandatory config values, warning on any deviation.
        for key, required_value in _REQUIRED_BT_VALUES.items():
            if key in bt_section:
                current = bt_section[key]
                if current != required_value:
                    log.warning(
                        f"BT config '{key}' was {current!r} in {p} — "
                        f"overriding to required value {required_value!r}"
                    )
                    bt_section[key] = required_value
                    changed = True

        # Ensure StateMapper mapping for L2CAP exists.
        state_mapper = cfg.setdefault("config", {}).setdefault("StateMapper", {})
        mapping = state_mapper.setdefault("Mapping", [])
        if isinstance(mapping, list):
            target_entry = {
                "AppendSummary": False,
                "Filter": "btl2cap",
                "LayerName": "L2CAP",
                "StateNameField": "btl2cap.cid",
            }
            has_mapping = False
            for entry in mapping:
                if (
                    isinstance(entry, dict)
                    and entry.get("Filter") == target_entry["Filter"]
                    and entry.get("LayerName") == target_entry["LayerName"]
                    and entry.get("StateNameField") == target_entry["StateNameField"]
                ):
                    has_mapping = True
                    break
            if not has_mapping:
                mapping.append(target_entry)
                changed = True

        if changed:
            with open(p, "w") as f:
                json.dump(cfg, f, indent=4)
            log.info(
                f"Patched BT config (TargetBDAddress={profile.target_address}, "
                f"BridgeHCI=true, InterceptTX=true, LMPSniffing=true, "
                f"RXBypassOnDemand=false) in {p}"
            )


# ── Device Registry ─────────────────────────────────────────────────────────
#
# Maps (protocol, device_id) → {"exploiter_factory": ..., "device_utils_factory": ...}
# Factory signatures:
#   exploiter_factory(profile: DeviceProfile, wd_tool, **kwargs) -> exploiter
#   device_utils_factory(profile: DeviceProfile, **kwargs) -> device_utils


def _make_oneplus_exploiter(
    profile: DeviceProfile, wd_tool: object, **kwargs: object
) -> object:
    from upstream.exploiter.oneplus_fiveg import OnePlus5GExploiter

    assert isinstance(profile, FivegProfile)
    return OnePlus5GExploiter(
        run_dir=kwargs["run_dir"],
        modem_timeout=kwargs.get("modem_timeout", 45),
        exploit_timeout=kwargs.get("exploit_timeout", 45),
        timeout_exploit_timeout=kwargs.get("timeout_exploit_timeout", 45),
        wd_tool=wd_tool,
        protocol=profile.protocol,
        log_subdir=profile.log_subdir,
        capture_filename=profile.capture_filename,
        monitor_log=profile.crash_oracle.get("monitor_log", "monitor.1.txt"),
    )


def _make_oneplus_utils(profile: DeviceProfile, **kwargs: object) -> object:
    from upstream.llm_fuzz import OnePlusUtils

    assert isinstance(profile, FivegProfile)
    return OnePlusUtils(
        ref_packets_paths=[profile.normal_capture, profile.fuzz_capture],
        crash_signatures_path=profile.crash_signatures_path,
        crash_id_field=profile.crash_oracle.get("crash_id_field", "sModemReason"),
        crash_id_regex=profile.crash_oracle.get("crash_id_regex", r"cause:(.*)"),
        monitor_log=profile.crash_oracle.get("monitor_log", "monitor.1.txt"),
        capture_filename=profile.capture_filename,
    )


def _make_bluetooth_exploiter(
    profile: DeviceProfile, wd_tool: object, **kwargs: object
) -> object:
    from upstream.exploiter.esp32_bt import ESP32BtExploiter

    assert isinstance(profile, BtProfile)
    return ESP32BtExploiter(
        run_dir=kwargs["run_dir"],
        target=profile.target_address,
        target_port=kwargs.get("target_port", "/dev/ttyUSB2"),
        target_hub_port=kwargs.get(
            "target_hub_port", 2
        ),  # TODO: this config should come from command line, or profile.json, but i suggest from command line because hub location is not a property of test device
        host_port=kwargs.get("host_port", "/dev/ttyUSB1"),
        exploit_timeout=kwargs.get("exploit_timeout", 45),
        wd_tool=wd_tool,
        log_subdir=profile.log_subdir,
        capture_filename=profile.capture_filename,
        monitor_log=profile.crash_oracle.get("monitor_log", "monitor.1.txt"),
    )


def _make_bluetooth_utils(profile: DeviceProfile, **kwargs: object) -> object:
    from upstream.utils.target_device.esp32_bt import BluetoothUtils

    assert isinstance(profile, BtProfile)
    return BluetoothUtils(
        ref_packets_paths=[profile.normal_capture, profile.fuzz_capture],
        crash_signatures_path=profile.crash_signatures_path,
        monitor_log=profile.crash_oracle.get("monitor_log", "monitor.1.txt"),
        capture_filename=profile.capture_filename,
    )


DEVICE_REGISTRY: dict[tuple[str, str], dict[str, object]] = {
    ("fiveg", "mediatek"): {
        "exploiter_factory": _make_oneplus_exploiter,
        "device_utils_factory": _make_oneplus_utils,
    },
    ("fiveg", "mediatek_d9400"): {
        "exploiter_factory": _make_oneplus_exploiter,
        "device_utils_factory": _make_oneplus_utils,
    },
    ("fiveg", "mediatek_d6300"): {
        "exploiter_factory": _make_oneplus_exploiter,
        "device_utils_factory": _make_oneplus_utils,
    },
    ("fiveg", "mediatek_d9000"): {
        "exploiter_factory": _make_oneplus_exploiter,
        "device_utils_factory": _make_oneplus_utils,
    },
    ("fiveg", "unisoc_ud710"): {
        "exploiter_factory": _make_oneplus_exploiter,
        "device_utils_factory": _make_oneplus_utils,
    },
    ("bt", "esp32"): {
        "exploiter_factory": _make_bluetooth_exploiter,
        "device_utils_factory": _make_bluetooth_utils,
    },
}


def get_exploiter(
    device: str,
    protocol: str,
    profile: DeviceProfile,
    wd_tool: object,
    **kwargs: object,
) -> object:
    """Create an exploiter instance for the given device.

    Args:
        device:      Device ID (e.g. "mediatek", "esp32").
        protocol:    Protocol string (e.g. "fiveg", "bt").
        profile:     Loaded DeviceProfile (or subclass) for the device.
        wd_tool:     Initialized WDissectorTool instance.
        **kwargs:    Passed through to the factory (run_dir, hub_loc, etc.).

    Raises:
        ValueError: If no registry entry exists for the given device.
        NotImplementedError: If the factory is not yet implemented (None).
    """
    key = (protocol, device)
    if key not in DEVICE_REGISTRY:
        raise ValueError(
            f"No DEVICE_REGISTRY entry for device='{device}', protocol='{protocol}'"
        )
    factory = DEVICE_REGISTRY[key]["exploiter_factory"]
    if factory is None:
        raise NotImplementedError(
            f"exploiter_factory for device='{device}' (protocol='{protocol}') "
            f"is not yet implemented."
        )
    return factory(profile, wd_tool, **kwargs)  # type: ignore[operator]


def get_device_utils(
    device: str,
    protocol: str,
    profile: DeviceProfile,
    **kwargs: object,
) -> object:
    """Create a device-utils instance for the given device.

    Args:
        device:      Device ID (e.g. "mediatek", "esp32").
        protocol:    Protocol string (e.g. "fiveg", "bt").
        profile:     Loaded DeviceProfile (or subclass) for the device.
        **kwargs:    Passed through to the factory.

    Raises:
        ValueError: If no registry entry exists for the given device.
        NotImplementedError: If the factory is not yet implemented (None).
    """
    key = (protocol, device)
    if key not in DEVICE_REGISTRY:
        raise ValueError(
            f"No DEVICE_REGISTRY entry for device='{device}', protocol='{protocol}'"
        )
    factory = DEVICE_REGISTRY[key]["device_utils_factory"]
    if factory is None:
        raise NotImplementedError(
            f"device_utils_factory for device='{device}' (protocol='{protocol}') "
            f"is not yet implemented."
        )
    return factory(profile, **kwargs)  # type: ignore[operator]
