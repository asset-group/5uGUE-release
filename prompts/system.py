import os

from version_config import FuzzerVersion, VersionConfig

# Define directories relative to prompts directory
_PROMPTS_PATH = os.path.dirname(os.path.abspath(__file__))
_WDISSECTOR_PATH = os.path.dirname(os.path.dirname(_PROMPTS_PATH))


def _get_templates(protocol: str):
    """Dynamic dispatcher to import templates based on device type."""
    if protocol == "bt":
        import prompts.bt.templates as templates
    else:
        import prompts.fiveg.templates as templates
    return templates


def _build_role_section(profile=None) -> str:
    """Build the role + constraints section from profile or defaults."""
    protocol = profile.protocol if profile else "fiveg"
    t = _get_templates(protocol)

    if profile:
        role_desc = profile.role_description
        oracle = profile.crash_oracle
        logcat_patterns = ", ".join(f'"{p}"' for p in oracle.get("logcat_patterns", []))
        crash_id_field = oracle.get("crash_id_field", "crash ID")
    else:
        role_desc = t.ROLE_DESC_DEFAULT
        logcat_patterns = t.LOGCAT_PATTERNS_DEFAULT
        crash_id_field = t.CRASH_ID_FIELD_DEFAULT

    constraints = t.CONSTRAINTS_TEMPLATE.format(
        logcat_patterns=logcat_patterns,
        crash_id_field=crash_id_field,
    )

    return f"""\
{role_desc}

## Constraints
{constraints}
"""


BATCH_TESTING_CONSTRAINT = """\
- **Batch testing**: When you have multiple test hypotheses ready (e.g., trying different values at the same offset, or testing variations of a pattern), use `execute_test_batch` to run up to 5 tests in one call. Plan all exploit code upfront. After the batch completes, call `save_finding` for each significant result.
"""


def _get_workflow(
    config: VersionConfig, protocol: str, post_first_crash: bool = False
) -> str:
    """Return version-appropriate and protocol-appropriate workflow section."""
    t = _get_templates(protocol)
    if config.version == FuzzerVersion.V1:
        return t.WORKFLOW_V1
    elif config.version == FuzzerVersion.V2:
        return t.WORKFLOW_V2_POST_FIRST_CRASH if post_first_crash else t.WORKFLOW_V2
    elif config.version == FuzzerVersion.V3F:
        return t.WORKFLOW_V3F_POST_FIRST_CRASH if post_first_crash else t.WORKFLOW_V3F
    else:
        return (
            t.WORKFLOW_V3_AND_FULL_POST_FIRST_CRASH
            if post_first_crash
            else t.WORKFLOW_V3_AND_FULL
        )


POST_FIRST_CRASH_DIRECTIVE = """\
## ACTIVE DIRECTIVE: NOVEL CRASH DISCOVERY MODE
You have confirmed your toolchain triggers crashes. Your objective has changed.

**YOUR ONLY GOAL**: Find crashes classified as `non_publicly_known_crash` or `fully_novel_crash`.

**What has worked historically** (stay close to known vulnerable areas):
- **Value variants at the same offset** — different values at a confirmed crash offset often trigger different crash signatures. Try values close to the original, boundary values, and values producing different ASN.1 interpretations.
- **Adjacent offset exploration** — bytes ±1 to ±6 from confirmed crash offsets share similar parser weaknesses. Fill in gaps between known crash zones.
- **Multi-field value combinations** — vary both bytes in confirmed multi-byte crashes to reach different crash components.
- **Inner byte deletion** — zero individual bytes between known crash zones that have never been individually tested.
- If a test returns `publicly_known_crash`, try a different value at that offset — it may yield a non-public or novel crash.
- After every test, immediately call `save_finding` + `update_strategy` in the same response. Update your exhausted offset+value list so you never repeat a combination.
- When sweeping adjacent offsets or value ranges, batch 3-5 variations and run them together.
"""

GITHUB_NAVIGATION = """\
### GitHub Repository Navigation
When you find a GitHub repository with exploit source code:
1. **Browse directories**: Use `fetch_url` on directory URLs (e.g. `github.com/owner/repo/tree/master/path`) to see file listings with download URLs.
2. **Read raw code**: Use `fetch_url` on `raw.githubusercontent.com` URLs (shown in directory listings) for clean source code.
3. **Navigate step by step**: repo root → subdirectory → source file. Don't guess file paths — browse the directory tree to find the correct path.
"""

GENERIC_DEBUGGING = """\
## Debugging Tips
- If `mutation_count` is 0, your filter is wrong — inspect reference packets to fix it before trying new strategies.
- If `total_packets` < 30, the target rejected early — target a later-stage packet or use a subtler mutation.
- After 3+ failures with the same category, switch to a different mutation category.
- **IMPORTANT**: For any tool that requires `capture_path`, use the baseline path shown below. NEVER guess or invent capture file paths.
"""


def build_system_prompt(
    strategy: str = "",
    config: VersionConfig | None = None,
    capture_path: str = "",
    post_first_crash: bool = False,
    profile=None,
) -> str:
    """Build the system prompt, composing sections based on version config and device type."""
    if config is None:
        from version_config import get_version_config

        config = get_version_config("full")

    protocol = profile.protocol if profile else "fiveg"
    t = _get_templates(protocol)

    # Extract profile values for template substitution
    if profile:
        search_examples = profile.web_search_examples
        header_offset = profile.header_offset
        exploit_prefix = profile.exploit_prefix
        vendor = profile.vendor
        device = profile.device
    else:
        if protocol == "bt":
            search_examples = [
                "ESP32 Bluetooth CVE crash",
                "Bluetooth L2CAP buffer overflow",
            ]
            header_offset = 0
            exploit_prefix = ""  # Bluetooth exploits does not have naming requirement
            vendor = "Espressif"
            device = "esp32"
        else:
            search_examples = [
                "MediaTek modem CVE RRC crash",
                "5G baseband ASN.1 buffer overflow",
            ]
            header_offset = 48
            exploit_prefix = "mac_sch_"
            vendor = "MediaTek"
            device = "OnePlus"

    search_example_1 = (
        search_examples[0] if len(search_examples) > 0 else "exploit CVE crash"
    )
    search_example_2 = (
        search_examples[1] if len(search_examples) > 1 else "vulnerability"
    )

    parts = [_build_role_section(profile)]

    if config.enable_batch_testing:
        parts.append(BATCH_TESTING_CONSTRAINT)

    parts.append(_get_workflow(config, protocol, post_first_crash))
    parts.append(t.MUTATION_TAXONOMY)

    if config.include_crash_patterns:
        crash_knowledge = profile.prompt_crash_knowledge if profile else ""
        if crash_knowledge:
            parts.append(crash_knowledge)

    if config.include_strategy_hints:
        strategy_hints = profile.prompt_strategy_hints if profile else ""
        if strategy_hints:
            parts.append(strategy_hints)

    if post_first_crash:
        parts.append(POST_FIRST_CRASH_DIRECTIVE)

    if config.enable_github_fetch:
        parts.append(GITHUB_NAVIGATION)

    parts.append(GENERIC_DEBUGGING)

    # Each protocol's templates module owns its own WDISSECTOR_API constant.
    parts.append(t.WDISSECTOR_API)

    if capture_path:
        parts.append(f"""\
## Baseline Capture Path
The baseline capture file is: `{capture_path}`
Use this exact path for ALL tool calls that require a `capture_path` parameter (list_packet_types, inspect_packets, get_field_info, get_packet_hex, etc.). Do NOT use any other path unless a test result provides a specific capture path.
""")

    prompt = "\n".join(parts)

    # Substitute template placeholders
    prompt = prompt.replace("{search_example_1}", search_example_1)
    prompt = prompt.replace("{search_example_2}", search_example_2)
    prompt = prompt.replace("{header_offset}", str(header_offset))
    prompt = prompt.replace("{exploit_prefix}", exploit_prefix)
    prompt = prompt.replace("{vendor}", vendor)
    prompt = prompt.replace("{device}", device)

    if config.version == "full":
        try:
            from prompts.user_custom_instructions import (
                USER_CUSTOM_INSTRUCTIONS_BT,
                USER_CUSTOM_INSTRUCTIONS_FIVEG,
            )
        except ImportError:
            from prompts.user_custom_instructions import (
                USER_CUSTOM_INSTRUCTIONS as legacy_instructions,
            )

            USER_CUSTOM_INSTRUCTIONS_FIVEG = legacy_instructions
            USER_CUSTOM_INSTRUCTIONS_BT = ""

        custom_instructions = (
            USER_CUSTOM_INSTRUCTIONS_BT
            if protocol == "bt"
            else USER_CUSTOM_INSTRUCTIONS_FIVEG
        )
        if custom_instructions:
            prompt += f"\n## Custom Instructions\n{custom_instructions}\n"

    if strategy:
        prompt += f"\n## Your Current Strategy (from previous turns)\n{strategy}\n"

    return prompt


def build_known_crashes_briefing(known_crashes_path: str | None = None) -> str:
    """Load confirmed crash data for the agent's initial context."""
    import json

    if known_crashes_path is None:
        from constants import KNOWN_CRASHES

        known_crashes_path = KNOWN_CRASHES
    try:
        with open(known_crashes_path, "r") as f:
            data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return ""

    crashes = data.get("confirmed_crashes", [])
    if not crashes:
        return ""

    lines = [
        "\n## Reference: Confirmed Crash Exploit Code Patterns",
        "These are the exact C exploit patterns that cause confirmed target crashes. Use them as templates for new variants.\n",
    ]
    for c in crashes:
        muts = ", ".join(
            f"pkt_buf[{m['offset_from_header']}] = {m['value']}" for m in c["mutations"]
        )
        lines.append(
            f"- **{c['name']}**: filter=`{c['filter']}` | `{muts}` | "
            f"component={c['crash_component']} | category={c['category']}"
        )

    lines.append(
        "\nFirst confirm at least one of these crashes still works on the current firmware — "
        "a working crash proves your toolchain is functional. Then use it as a foundation to "
        "find NEW crashes: try adjacent offsets, different values, unexplored substructures, and combinations."
    )
    return "\n".join(lines)


def build_initial_briefing(
    packet_summary: str, capture_path: str = "", profile=None
) -> str:
    device_name = profile.device if profile else "target"
    protocol = profile.protocol if profile else "fiveg"
    t = _get_templates(protocol)

    capture_note = ""
    if capture_path:
        capture_note = f"""
IMPORTANT: The baseline capture file path is:
  {capture_path}
Use this exact path for all tool calls that require a capture_path parameter (inspect_packets, get_field_info, get_packet_hex, view_state_machine, etc.).\
"""
    return t.INITIAL_BRIEFING_TEMPLATE.format(
        device_name=device_name,
        capture_note=capture_note,
        packet_summary=packet_summary,
    )


_FRIENDLY_PROTOCOL_NAMES = {
    "bt": "Bluetooth Classic",
    "fiveg": "5G NR",
}


def build_cold_start_prompt(
    target_vendor: str = "MediaTek",
    protocol: str = "fiveg",
) -> str:
    """Prompt injected in cold-start mode to force research-first workflow."""
    friendly_protocol_name = _FRIENDLY_PROTOCOL_NAMES.get(protocol, "5G NR")
    t = _get_templates(protocol)
    return t.COLD_START_TEMPLATE.format(
        target_vendor=target_vendor,
        friendly_protocol_name=friendly_protocol_name,
    )


def build_research_prompt(
    config: VersionConfig,
    target_vendor: str = "MediaTek",
    protocol: str = "fiveg",
    profile=None,
) -> str:
    """Build a research prompt for V1/V2/V3/V3F modes (no prior crash knowledge)."""
    if config.version == FuzzerVersion.FULL:
        return ""

    if profile:
        protocol = profile.protocol

    friendly_protocol_name = _FRIENDLY_PROTOCOL_NAMES.get(protocol, "5G NR")
    t = _get_templates(protocol)

    # Clear parts to prevent duplicating the Discovery Mode header,
    # because both RESEARCH_TEMPLATE and RESEARCH_TEMPLATE_V3F already contain it.
    parts = []
    template = (
        t.RESEARCH_TEMPLATE_V3F
        if config.version == FuzzerVersion.V3F
        else t.RESEARCH_TEMPLATE
    )
    parts.append(
        template.format(
            target_vendor=target_vendor,
            friendly_protocol_name=friendly_protocol_name,
        )
    )

    if profile and getattr(profile, "prompt_research_hints", ""):
        parts.append("\n" + profile.prompt_research_hints)
    return "\n".join(parts)
