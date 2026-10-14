import pytest
from prompts.system import build_cold_start_prompt, build_system_prompt


# ── Helpers ───────────────────────────────────────────────────────────────────


class _FakeProfile:
    """Minimal stand-in for a real DeviceProfile; overrides protocol-specific fields."""

    def __init__(self, protocol: str):
        self.protocol = protocol
        self.vendor = "Espressif" if protocol == "bt" else "MediaTek"
        self.device = "esp32" if protocol == "bt" else "OnePlus"
        self.role_description = f"{protocol} researcher against an {{vendor}} {{device}} target"
        self.crash_oracle = {
            "logcat_patterns": ["bt_crash" if protocol == "bt" else "modem_failure"],
            "crash_id_field": "bt_crash" if protocol == "bt" else "sModemReason",
        }
        self.web_search_examples = ["CVE example"]
        self.header_offset = 0 if protocol == "bt" else 48
        self.exploit_prefix = "" if protocol == "bt" else "mac_sch_"
        self.prompt_crash_knowledge = ""
        self.prompt_strategy_hints = ""
        self.prompt_research_hints = ""


# ── build_cold_start_prompt ───────────────────────────────────────────────────


def test_build_cold_start_prompt_defaults():
    # Test default arguments (MediaTek, 5G NR, fiveg)
    prompt = build_cold_start_prompt()
    assert "MediaTek" in prompt
    assert "5G NR" in prompt
    assert "RRC vulnerability" in prompt
    assert "NAS vulnerability" in prompt
    assert "baseband vulnerability" in prompt
    assert "RLC vulnerability" in prompt
    assert "L2CAP" not in prompt


def test_build_cold_start_prompt_fiveg():
    # Test custom values for fiveg
    prompt = build_cold_start_prompt(
        target_vendor="MediaTek",
        protocol="fiveg",
    )
    assert "MediaTek" in prompt
    assert "5G NR" in prompt
    assert "RRC vulnerability" in prompt
    assert "L2CAP" not in prompt


def test_build_cold_start_prompt_bt():
    # Test bluetooth values
    prompt = build_cold_start_prompt(
        target_vendor="Espressif",
        protocol="bt",
    )
    assert "Espressif" in prompt
    assert "Bluetooth Classic" in prompt
    assert "L2CAP vulnerability" in prompt
    assert "SDP vulnerability" in prompt
    assert "LMP vulnerability" in prompt
    assert "RRC vulnerability" not in prompt


def test_build_cold_start_prompt_fallback():
    # Test that any other protocol falls back to fiveg
    prompt = build_cold_start_prompt(
        target_vendor="UnknownVendor",
        protocol="unknown_protocol",
    )
    assert "UnknownVendor" in prompt
    assert "5G NR" in prompt  # falls back to 5G NR friendly name
    assert "RRC vulnerability" in prompt


# ── build_system_prompt: BT protocol ─────────────────────────────────────────


class TestBuildSystemPromptBT:
    """build_system_prompt() with protocol='bt' should include BT-specific API content."""

    def setup_method(self):
        from version_config import get_version_config

        self.cfg = get_version_config("full")
        self.profile = _FakeProfile("bt")
        self.prompt = build_system_prompt(config=self.cfg, profile=self.profile)

    def test_uses_bt_fuzzer(self):
        assert "bt_fuzzer" in self.prompt

    def test_does_not_use_lte_fuzzer(self):
        assert "lte_fuzzer" not in self.prompt

    def test_contains_bt_config_required_fields(self):
        """Required BT config fields must be documented."""
        assert "bridge_hci" in self.prompt
        assert "intercept_tx" in self.prompt
        assert "lmp_sniffing" in self.prompt
        assert "rx_bypass_on_demand" in self.prompt

    def test_contains_bt_config_tunable_fields(self):
        """User-tunable fields must also be mentioned."""
        assert "disable_role_switch" in self.prompt
        assert "rx_bypass" in self.prompt

    def test_no_5g_exemplar_filter(self):
        """The WDISSECTOR_API section of the BT prompt must not contain the 5G filter.

        We only check the API reference section itself (not the full prompt) because
        user custom instructions may legitimately include 5G code examples.
        """
        # Check the BT template constant directly rather than slicing the assembled
        # prompt, which may have user custom instructions appended after the API header.
        import prompts.bt.templates as bt_templates
        assert "nr-rrc.rrcSetup_element" not in bt_templates.WDISSECTOR_API

    def test_uses_op_exemplar_filter(self):
        assert "btbrlmp.op == 40" in self.prompt

    def test_no_stale_placeholders(self):
        """No unreplaced template placeholders should survive."""
        assert "{fuzzer_name}" not in self.prompt
        assert "{exemplar_filter}" not in self.prompt

    def test_vendor_and_device_substituted(self):
        """The {vendor} and {device} placeholders must be resolved."""
        assert "{vendor}" not in self.prompt
        assert "{device}" not in self.prompt
        assert "Espressif" in self.prompt
        assert "esp32" in self.prompt

    def test_bt_custom_instructions_isolation(self):
        """Bluetooth prompt must include BT custom instructions and exclude fiveg custom instructions."""
        assert "Bluetooth Custom Instructions" in self.prompt
        assert "RRC Setup" not in self.prompt

    def test_bt_exploit_naming_requirement_resolved(self):
        """Should not contain the broken 'MUST start with  prefix' instruction."""
        assert "MUST start with" not in self.prompt
        assert "Bluetooth exploits do not have any naming or prefix requirements." in self.prompt



# ── build_system_prompt: 5G protocol ─────────────────────────────────────────


class TestBuildSystemPrompt5G:
    """build_system_prompt() with protocol='fiveg' should include 5G-specific API content."""

    def setup_method(self):
        from version_config import get_version_config

        self.cfg = get_version_config("full")
        self.profile = _FakeProfile("fiveg")
        self.prompt = build_system_prompt(config=self.cfg, profile=self.profile)

    def test_uses_lte_fuzzer(self):
        assert "lte_fuzzer" in self.prompt

    def test_does_not_use_bt_fuzzer(self):
        assert "bt_fuzzer" not in self.prompt

    def test_uses_5g_exemplar_filter(self):
        assert "nr-rrc.rrcSetup_element" in self.prompt

    def test_no_bt_config_fields(self):
        """BT-specific config fields must not appear in the 5G prompt."""
        assert "bridge_hci" not in self.prompt
        assert "disable_role_switch" not in self.prompt

    def test_no_stale_placeholders(self):
        assert "{fuzzer_name}" not in self.prompt
        assert "{exemplar_filter}" not in self.prompt

    def test_header_offset_substituted(self):
        """The {header_offset} placeholder must be resolved to the numeric value."""
        assert "{header_offset}" not in self.prompt
        assert "48" in self.prompt

    def test_vendor_and_device_substituted(self):
        """The {vendor} and {device} placeholders must be resolved."""
        assert "{vendor}" not in self.prompt
        assert "{device}" not in self.prompt
        assert "MediaTek" in self.prompt
        assert "OnePlus" in self.prompt

    def test_fiveg_custom_instructions_isolation(self):
        """fiveg prompt must include fiveg custom instructions and exclude BT custom instructions."""
        assert "RRC Setup" in self.prompt
        assert "Bluetooth Custom Instructions" not in self.prompt
