from tools.packet_tools import get_packet_tools
from tools.protocol_tools import get_protocol_tools
from tools.state_tools import get_state_tools
from tools.crash_tools import get_crash_tools
from tools.exploit_tools import get_exploit_tools
from tools.memory_tools import get_memory_tools
from tools.web_tools import get_web_tools
from tools.paper_tools import get_paper_tools
from tools.adb_tools import get_adb_tools
from device_profile import FivegProfile


def build_tool_registry(
    wd_tool,
    td_utils,
    engine,
    kb,
    target_vendor: str = "MediaTek",
    target_protocol: str = "5G NR",
    config=None,
    session_exploits: set | None = None,
    profile=None,
):
    """Build the complete tool registry for the agent.

    Args:
        config: VersionConfig. Controls which tools are registered.
                If None, all tools are registered (backward compatible / FULL mode).
        session_exploits: Set tracking exploit files created during this session.
                          Shared with exploit tools for restricted mode.
        profile: DeviceProfile (or subclass). If provided, threads device-specific
                 values to tools. ADB tools are only registered for FivegProfile.

    Returns a dict mapping tool names to (schema, handler) tuples.
    - schema: tool definition dict (name, description, input_schema)
    - handler: callable(params_dict) -> str
    """
    # Extract profile values (with fallbacks for backward compat)
    exploit_folder = profile.exploit_folder if profile else None
    known_crashes_path = profile.known_crashes_path if profile else None
    # adb_serial is only present on FivegProfile; other device types do not use ADB.
    adb_serial = profile.adb_serial if isinstance(profile, FivegProfile) else None
    normal_capture = profile.normal_capture if profile else None

    if profile:
        target_vendor = profile.vendor
        target_protocol = profile.protocol

    tools = {}
    tools.update(get_packet_tools(wd_tool, td_utils, normal_capture=normal_capture))
    tools.update(get_protocol_tools())
    tools.update(get_state_tools(wd_tool))
    tools.update(get_crash_tools(td_utils))
    exploit_prefix = profile.exploit_prefix if profile else "mac_sch_"

    if isinstance(profile, FivegProfile):
        tools.update(get_adb_tools(adb_serial=adb_serial))
    tools.update(
        get_exploit_tools(
            wd_tool,
            td_utils,
            engine,
            config=config,
            session_exploits=session_exploits,
            exploit_folder=exploit_folder,
            known_crashes_path=known_crashes_path,
            exploit_prefix=exploit_prefix,
        )
    )
    tools.update(get_memory_tools(kb, config=config))

    # Web tools: only registered when enabled (or when config is None = FULL)
    if config is None or config.enable_web_tools:
        tools.update(
            get_web_tools(kb, target_vendor, target_protocol, config=config)
        )

    # Paper tools: only registered when enabled (or config is None = FULL)
    if config is None or config.enable_local_papers:
        tools.update(get_paper_tools(kb, target_vendor, target_protocol))

    return tools
