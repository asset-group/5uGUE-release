"""Tests for the device profile system.

Covers:
- DeviceProfile base contract (shared fields present on all subclasses)
- FivegProfile (all six modem variants)
- BtProfile (esp32 skeleton)
- DEVICE_REGISTRY consistency
- load_device_profile error handling
- list_available_devices
- get_active_device fallback
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from device_profile import (
    BT_REQUIRED_FIELDS,
    DEVICE_REGISTRY,
    FIVEG_REQUIRED_FIELDS,
    BtProfile,
    DeviceProfile,
    FivegProfile,
    get_active_device,
    list_available_devices,
    load_device_profile,
)

# ── Helpers ──────────────────────────────────────────────────────────────────


def _profile_dir(protocol: str, device: str) -> str:
    agent_path = os.path.join(os.path.dirname(__file__), "..")
    return os.path.abspath(
        os.path.join(agent_path, "data", "devices", protocol, device)
    )


# ── Base contract: all DeviceProfile subclasses expose base fields ────────────


class TestDeviceProfileBaseContract:
    """Verify that all required base fields are accessible on both subclasses."""

    @pytest.mark.parametrize(
        "device,protocol",
        [
            ("mediatek", "fiveg"),
            ("esp32", "bt"),
        ],
    )
    def test_base_fields_present(self, device: str, protocol: str) -> None:
        p = load_device_profile(device, protocol)
        assert isinstance(p, DeviceProfile)
        assert p.protocol == protocol
        assert p.vendor
        assert p.device
        assert p.protocol
        assert isinstance(p.header_offset, int)
        assert p.capture_filename
        assert isinstance(p.exploit_prefix, str)
        assert p.exploit_folder_name
        assert p.log_subdir
        assert isinstance(p.crash_oracle, dict)
        assert p.role_description
        assert isinstance(p.web_search_examples, list)
        assert len(p.web_search_examples) >= 1
        assert p.profile_dir
        assert p.known_crashes_path
        assert p.crash_signatures_path
        assert p.normal_capture
        assert p.fuzz_capture
        assert p.exploit_folder
        assert p.log_subdir_path
        assert isinstance(p.prompt_crash_knowledge, str)
        assert isinstance(p.prompt_strategy_hints, str)
        assert isinstance(p.prompt_research_hints, str)


# ── FivegProfile: MediaTek (base OnePlus variant) ────────────────────────────


class TestLoadMediatekProfile:
    def test_loads_as_modem_profile(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert isinstance(p, FivegProfile)

    def test_protocol_field(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert p.protocol == "fiveg"

    def test_vendor_and_device(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert p.vendor == "MediaTek"
        assert p.device == "OnePlus"

    def test_protocol(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert p.protocol == "fiveg"

    def test_crash_oracle_fields(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert p.crash_oracle["crash_id_field"] == "sModemReason"
        assert p.crash_oracle["crash_id_regex"] == "cause:(.*)"
        assert p.crash_oracle["monitor_log"] == "monitor.1.txt"
        assert len(p.crash_oracle["logcat_patterns"]) > 0

    def test_exploit_prefix(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert p.exploit_prefix == "mac_sch_"

    def test_header_offset(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert p.header_offset == 48

    def test_capture_filename(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert p.capture_filename == "capture_nr5g_gnb.pcapng"

    def test_exploit_folder_name(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert p.exploit_folder_name == "5gnr_gnb"

    def test_log_subdir(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert p.log_subdir == "5gnr_gnb"

    def test_web_search_examples(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert len(p.web_search_examples) >= 1
        assert "MediaTek" in p.web_search_examples[0]

    def test_adb_serial(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert isinstance(p.adb_serial, str)

    def test_adb_grep_hints(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert "mediatek" in p.adb_grep_hints
        assert "mtk" in p.adb_grep_hints


class TestMediatekProfilePaths:
    def test_known_crashes_exists(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert os.path.isfile(p.known_crashes_path)

    def test_crash_signatures_exists(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert os.path.isfile(p.crash_signatures_path)

    def test_normal_capture_exists(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert os.path.exists(p.normal_capture), f"Missing: {p.normal_capture}"

    def test_fuzz_capture_exists(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert os.path.exists(p.fuzz_capture), f"Missing: {p.fuzz_capture}"

    def test_exploit_folder_exists(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert os.path.isdir(p.exploit_folder)

    def test_known_crashes_valid_json(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        with open(p.known_crashes_path) as f:
            data = json.load(f)
        assert "confirmed_crashes" in data
        assert len(data["confirmed_crashes"]) == 7


class TestMediatekProfilePrompts:
    def test_crash_knowledge_loaded(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert len(p.prompt_crash_knowledge) > 100
        assert "MediaTek" in p.prompt_crash_knowledge

    def test_strategy_hints_loaded(self) -> None:
        p = load_device_profile("mediatek", "fiveg")
        assert len(p.prompt_strategy_hints) > 50
        assert "adjacent" in p.prompt_strategy_hints.lower()


# ── FivegProfile: MediaTek D9400 ─────────────────────────────────────────────


class TestLoadMediatekD9400Profile:
    def test_loads_as_modem_profile(self) -> None:
        p = load_device_profile("mediatek_d9400", "fiveg")
        assert isinstance(p, FivegProfile)

    def test_vendor_and_device(self) -> None:
        p = load_device_profile("mediatek_d9400", "fiveg")
        assert p.vendor == "MediaTek"
        assert "9400" in p.device

    def test_adb_serial(self) -> None:
        p = load_device_profile("mediatek_d9400", "fiveg")
        assert p.adb_serial == "STUB_ADB_SERIAL"

    def test_crash_oracle_fields(self) -> None:
        p = load_device_profile("mediatek_d9400", "fiveg")
        assert p.crash_oracle["crash_id_field"] == "sModemReason"
        assert p.crash_oracle["crash_id_regex"] == "cause:(.*)"
        assert p.crash_oracle["monitor_log"] == "monitor.1.txt"
        assert "sModemReason" in p.crash_oracle["logcat_patterns"]

    def test_protocol_config(self) -> None:
        p = load_device_profile("mediatek_d9400", "fiveg")
        assert p.exploit_prefix == "mac_sch_"
        assert p.header_offset == 48
        assert p.capture_filename == "capture_nr5g_gnb.pcapng"
        assert p.exploit_folder_name == "5gnr_gnb"

    def test_crash_id_regex_compiles(self) -> None:
        import re

        p = load_device_profile("mediatek_d9400", "fiveg")
        pattern = re.compile(p.crash_oracle["crash_id_regex"])
        assert pattern is not None

    def test_known_crashes_path_exists(self) -> None:
        p = load_device_profile("mediatek_d9400", "fiveg")
        assert os.path.isfile(p.known_crashes_path)

    def test_captures_exist(self) -> None:
        p = load_device_profile("mediatek_d9400", "fiveg")
        assert os.path.exists(p.normal_capture), f"Missing: {p.normal_capture}"
        assert os.path.exists(p.fuzz_capture), f"Missing: {p.fuzz_capture}"

    def test_in_registry(self) -> None:
        assert ("fiveg", "mediatek_d9400") in DEVICE_REGISTRY

    def test_prompt_files_loaded(self) -> None:
        p = load_device_profile("mediatek_d9400", "fiveg")
        assert len(p.prompt_crash_knowledge) > 50
        assert len(p.prompt_strategy_hints) > 50

    def test_research_hints_loaded(self) -> None:
        p = load_device_profile("mediatek_d9400", "fiveg")
        assert len(p.prompt_research_hints) > 50
        assert "5Ghoul" in p.prompt_research_hints


# ── FivegProfile: MediaTek D6300 ─────────────────────────────────────────────


class TestLoadMediatekD6300Profile:
    def test_loads_as_modem_profile(self) -> None:
        p = load_device_profile("mediatek_d6300", "fiveg")
        assert isinstance(p, FivegProfile)

    def test_vendor_and_device(self) -> None:
        p = load_device_profile("mediatek_d6300", "fiveg")
        assert p.vendor == "MediaTek"
        assert "REDMI" in p.device or "15C" in p.device

    def test_adb_serial(self) -> None:
        p = load_device_profile("mediatek_d6300", "fiveg")
        assert p.adb_serial == "STUB_ADB_SERIAL"

    def test_crash_oracle_fields_misight(self) -> None:
        """D6300 uses MiSightJni instead of sModemReason."""
        p = load_device_profile("mediatek_d6300", "fiveg")
        assert p.crash_oracle["crash_id_field"].startswith(
            "MiSight: Java_com_miui_misight_MiSight_nativeSendEvent"
        )
        assert "Type" in p.crash_oracle["crash_id_field"]
        assert "subsystem_modem" in p.crash_oracle["crash_id_field"]
        assert "Summary" in p.crash_oracle["crash_id_regex"]
        assert "ELM" in p.crash_oracle["crash_id_regex"]
        assert p.crash_oracle["monitor_log"] == "monitor.1.txt"

    def test_crash_id_regex_extracts_assert(self) -> None:
        import re

        p = load_device_profile("mediatek_d6300", "fiveg")
        pattern = re.compile(p.crash_oracle["crash_id_regex"])
        sample = (
            "[2026-04-23 15:43:03.943924] 04-23 15:42:37.652  3136  3555 "
            "D MiSightJni: MiSight: Java_com_miui_misight_MiSight_nativeSendEvent "
            'enter called. \'{"Type":"subsystem_modem","Digest":"abc",'
            '"CurrentTime":1776958957503,'
            r'"Summary":"(MCU_core0,vpe0,tc0(VPE0))\n[ASSERT] file:mcu\/l1\/nl1\/internal\/src\/rx\/nr_rx_dspcmd_ext_csif_csi.c line:2515\np1:0x00000000\np2:0x00000000\np3:0x00000000\n\n\nELM r\/wlat:PASS\n\n"'
            ',"Stacktrace":"..."}\''
        )
        assert p.crash_oracle["crash_id_field"] in sample
        m = pattern.search(sample)
        assert m is not None, "Regex failed to match the MiSightJni Summary block"
        captured = m.group(1)
        assert "[ASSERT]" in captured
        assert "nr_rx_dspcmd_ext_csif_csi.c" in captured
        assert "line:2515" in captured
        assert "p1:" not in captured

    def test_crash_id_regex_extracts_fatal_error(self) -> None:
        import re

        p = load_device_profile("mediatek_d6300", "fiveg")
        pattern = re.compile(p.crash_oracle["crash_id_regex"])
        sample = (
            "D MiSightJni: " + p.crash_oracle["crash_id_field"] + '","Digest":"x",'
            r'"Summary":"(MCU_core0)\n[Fatal error] err_code1:0x00000016 err_code2:0x7DBD0202 err_code3:0x00000000\nCaDeFa Supported\n\n\n\nELM r\/wlat:PASS\n\n"'
        )
        m = pattern.search(sample)
        assert m is not None
        captured = m.group(1)
        assert "[Fatal error]" in captured
        assert "0x00000016" in captured

    def test_prompt_files_loaded(self) -> None:
        p = load_device_profile("mediatek_d6300", "fiveg")
        assert len(p.prompt_crash_knowledge) > 50
        assert (
            "Dimensity 6300" in p.prompt_crash_knowledge
            or "MT6835" in p.prompt_crash_knowledge
        )
        assert len(p.prompt_strategy_hints) > 50

    def test_research_hints_v3_safe(self) -> None:
        """V3 evaluation safety: research_hints must not leak experimental ground truth."""
        p = load_device_profile("mediatek_d6300", "fiveg")
        text = p.prompt_research_hints
        assert len(text) > 50
        leak_values = [
            "0xd6",
            "0x82",
            "0x18",
            "0x28",
            "0x17",
            "0xee",
            "0x61",
            "0x4f",
            "0x30",
            "0x60",
            "0x33",
            "0xd8",
            "0xdc",
        ]
        for v in leak_values:
            assert v.lower() not in text.lower(), f"V3 leakage: {v} found"
        leak_fields = [
            "monitoringSymbolsWithinSlot",
            "reportQuantity",
            "pucch_Resource",
            "pdsch_ServingCellConfig",
            "csi_MeasConfig",
        ]
        for f in leak_fields:
            assert f not in text, f"V3 leakage: field {f} found"
        assert "mediatek_d9000" not in text
        assert "mediatek_d9400" not in text


# ── FivegProfile: MediaTek D9000 ─────────────────────────────────────────────


class TestLoadMediatekD9000Profile:
    def test_loads_as_modem_profile(self) -> None:
        p = load_device_profile("mediatek_d9000", "fiveg")
        assert isinstance(p, FivegProfile)

    def test_vendor_and_device(self) -> None:
        p = load_device_profile("mediatek_d9000", "fiveg")
        assert p.vendor == "MediaTek"
        assert "Nord 3" in p.device or "OnePlus" in p.device

    def test_adb_serial(self) -> None:
        p = load_device_profile("mediatek_d9000", "fiveg")
        assert p.adb_serial == "STUB_ADB_SERIAL"

    def test_crash_oracle_fields(self) -> None:
        p = load_device_profile("mediatek_d9000", "fiveg")
        assert p.crash_oracle["crash_id_field"] == "sModemReason"
        assert p.crash_oracle["crash_id_regex"] == "cause:(.*)"
        assert p.crash_oracle["monitor_log"] == "monitor.1.txt"
        assert "sModemReason" in p.crash_oracle["logcat_patterns"]

    def test_crash_id_regex_compiles_and_matches(self) -> None:
        import re

        p = load_device_profile("mediatek_d9000", "fiveg")
        pattern = re.compile(p.crash_oracle["crash_id_regex"])
        m = pattern.search(
            "sModemReason:fid:1234567890;cause:(MSONIC0) [ASSERT] file:dsp5/coresonic/msonic/foo.c line:42"
        )
        assert m is not None
        assert "(MSONIC0)" in m.group(1)
        assert "[ASSERT]" in m.group(1)

    def test_in_registry(self) -> None:
        assert ("fiveg", "mediatek_d9000") in DEVICE_REGISTRY

    def test_prompt_files_loaded(self) -> None:
        p = load_device_profile("mediatek_d9000", "fiveg")
        assert len(p.prompt_crash_knowledge) > 50
        assert (
            "Dimensity 9000" in p.prompt_crash_knowledge
            or "MT6983" in p.prompt_crash_knowledge
        )
        assert len(p.prompt_strategy_hints) > 50


# ── FivegProfile: Unisoc UD710 ───────────────────────────────────────────────


class TestLoadUnisocUD710Profile:
    def test_loads_as_modem_profile(self) -> None:
        p = load_device_profile("unisoc_ud710", "fiveg")
        assert isinstance(p, FivegProfile)

    def test_vendor_and_device(self) -> None:
        p = load_device_profile("unisoc_ud710", "fiveg")
        assert p.vendor == "Unisoc"
        assert "UD710" in p.device or "ud710" in p.device.lower()

    def test_adb_serial(self) -> None:
        p = load_device_profile("unisoc_ud710", "fiveg")
        assert p.adb_serial == "STUB_ADB_SERIAL"

    def test_crash_oracle_fields(self) -> None:
        p = load_device_profile("unisoc_ud710", "fiveg")
        assert p.crash_oracle["crash_id_field"] == "modemAsserInfo"
        assert "modemAsserInfo" in p.crash_oracle["crash_id_regex"]
        assert p.crash_oracle["monitor_log"] == "monitor.1.txt"
        assert "ModemAssertInfoActivity" in p.crash_oracle["logcat_patterns"]

    def test_adb_magic_words_present(self) -> None:
        p = load_device_profile("unisoc_ud710", "fiveg")
        assert p.crash_oracle.get("adb_magic_words") == ["modemAsserInfo"]

    def test_crash_id_regex_compiles_and_matches(self) -> None:
        import re

        p = load_device_profile("unisoc_ud710", "fiveg")
        pattern = re.compile(p.crash_oracle["crash_id_regex"])
        sample = "modemAsserInfo = Modem Assert: NRRC Task  PS CP assert in file nrrc_main.c line 4570 exp=0 info=[] mModemAssertCount = 251"
        m = pattern.search(sample)
        assert m is not None
        assert m.group(1).startswith("Modem Assert:")
        assert "mModemAssertCount" not in m.group(1)

    def test_in_registry(self) -> None:
        assert ("fiveg", "unisoc_ud710") in DEVICE_REGISTRY

    def test_prompt_files_loaded(self) -> None:
        p = load_device_profile("unisoc_ud710", "fiveg")
        assert len(p.prompt_crash_knowledge) > 50
        assert "UD710" in p.prompt_crash_knowledge
        assert len(p.prompt_strategy_hints) > 50

    def test_research_hints_loaded(self) -> None:
        p = load_device_profile("unisoc_ud710", "fiveg")
        assert len(p.prompt_research_hints) > 50
        assert "UD710" in p.prompt_research_hints


# ── BtProfile: esp32 skeleton ─────────────────────────────────────────


class TestLoadEsp32BTProfile:
    def test_loads_as_bluetooth_profile(self) -> None:
        p = load_device_profile("esp32", "bt")
        assert isinstance(p, BtProfile)

    def test_protocol_field(self) -> None:
        p = load_device_profile("esp32", "bt")
        assert p.protocol == "bt"

    def test_bt_specific_fields(self) -> None:
        p = load_device_profile("esp32", "bt")
        assert p.target_address == "24:0a:c4:61:1c:1a"

    def test_base_fields_accessible(self) -> None:
        p = load_device_profile("esp32", "bt")
        assert p.vendor == "Espressif"
        assert p.device == "esp32"
        assert p.protocol == "bt"
        assert p.crash_oracle
        assert p.role_description
        assert len(p.web_search_examples) >= 1

    def test_known_crashes_valid_json(self) -> None:
        p = load_device_profile("esp32", "bt")
        with open(p.known_crashes_path) as f:
            data = json.load(f)
        assert "confirmed_crashes" in data

    def test_crash_signatures_valid_json(self) -> None:
        p = load_device_profile("esp32", "bt")
        with open(p.crash_signatures_path) as f:
            data = json.load(f)
        assert "public" in data
        assert "non_public" in data

    def test_no_adb_serial_attribute(self) -> None:
        """BtProfile must NOT expose adb_serial — it is modem-only."""
        p = load_device_profile("esp32", "bt")
        assert not hasattr(p, "adb_serial")

    def test_in_registry(self) -> None:
        assert ("bt", "esp32") in DEVICE_REGISTRY


# ── Invalid / error paths ────────────────────────────────────────────────────


class TestLoadDeviceProfileErrors:
    def test_nonexistent_device(self) -> None:
        with pytest.raises(ValueError, match="not found"):
            load_device_profile("nonexistent_xyz", "fiveg")

    def test_error_lists_available_devices(self) -> None:
        with pytest.raises(ValueError, match="mediatek"):
            load_device_profile("nonexistent_xyz", "fiveg")

    def test_unknown_protocol(self) -> None:
        with pytest.raises(ValueError, match="Unknown protocol"):
            load_device_profile("mediatek", "fax_machine")

    def test_no_registry_entry_raises(self, tmp_path) -> None:
        """A profile directory without a registry entry raises ValueError."""
        import device_profile as dp

        # Temporarily inject a fake profile dir
        fake_device = "fake_unregistered"
        fake_dir = tmp_path / "fiveg" / fake_device
        fake_dir.mkdir(parents=True)
        profile_json = fake_dir / "profile.json"
        profile_json.write_text(
            json.dumps(
                {
                    "protocol": "fiveg",
                    "vendor": "X",
                    "device": "Y",
                    "protocol": "Z",
                    "header_offset": 0,
                    "capture_filename": "x.pcapng",
                    "exploit_prefix": "x_",
                    "exploit_folder_name": "x",
                    "log_subdir": "x",
                    "crash_oracle": {},
                    "role_description": "R",
                    "web_search_examples": ["X"],
                    "adb_serial": "",
                    "adb_grep_hints": [],
                }
            )
        )
        original_path = dp._DEVICES_PATH
        dp._DEVICES_PATH = str(tmp_path)
        try:
            with pytest.raises(ValueError, match="no DEVICE_REGISTRY entry"):
                load_device_profile(fake_device, "fiveg")
        finally:
            dp._DEVICES_PATH = original_path

    def test_bt_device_mismatch_raises(self, tmp_path) -> None:
        """For BT protocol, if the device field in profile.json does not match the directory name, raise ValueError."""
        import device_profile as dp

        fake_device = "fake_bt_device"
        fake_dir = tmp_path / "bt" / fake_device
        fake_dir.mkdir(parents=True)
        profile_json = fake_dir / "profile.json"
        profile_json.write_text(
            json.dumps(
                {
                    "vendor": "Espressif",
                    "device": "mismatched_device_name",
                    "protocol": "bt",
                    "header_offset": 0,
                    "capture_filename": "x.pcapng",
                    "exploit_prefix": "",
                    "exploit_folder_name": "x",
                    "log_subdir": "x",
                    "crash_oracle": {},
                    "role_description": "R",
                    "web_search_examples": ["X"],
                    "target_address": "24:0a:c4:61:1c:1a",
                }
            )
        )

        # Inject registry entry so registry check passes
        dp.DEVICE_REGISTRY[("bt", fake_device)] = {
            "exploiter_factory": lambda *a, **kw: None,
            "device_utils_factory": lambda *a, **kw: None,
        }

        original_path = dp._DEVICES_PATH
        dp._DEVICES_PATH = str(tmp_path)
        try:
            with pytest.raises(ValueError, match="does not match the folder name"):
                load_device_profile(fake_device, "bt")
        finally:
            dp._DEVICES_PATH = original_path
            dp.DEVICE_REGISTRY.pop(("bt", fake_device), None)


# ── list_available_devices ────────────────────────────────────────────────────


class TestListAvailableDevices:
    def test_lists_modem_devices(self) -> None:
        devices = list_available_devices("fiveg")
        assert "mediatek" in devices
        assert "unisoc_ud710" in devices

    def test_modem_list_is_sorted(self) -> None:
        devices = list_available_devices("fiveg")
        assert devices == sorted(devices)

    def test_lists_bluetooth_devices(self) -> None:
        devices = list_available_devices("bt")
        assert "esp32" in devices

    def test_lists_all_devices_without_type(self) -> None:
        all_devices = list_available_devices()
        # Should include cross-type entries as "type/device" strings
        assert any(e.startswith("fiveg/") for e in all_devices)
        assert any(e.startswith("bt/") for e in all_devices)

    def test_unknown_type_returns_empty(self) -> None:
        result = list_available_devices("fax_machine")
        assert result == []


# ── DEVICE_REGISTRY consistency ───────────────────────────────────────────────


class TestDeviceRegistry:
    def test_all_modem_profiles_have_registry_entry(self) -> None:
        for device in list_available_devices("fiveg"):
            key = ("fiveg", device)
            assert key in DEVICE_REGISTRY, (
                f"Modem '{device}' has profile directory but no DEVICE_REGISTRY entry"
            )

    def test_all_bt_profiles_have_registry_entry(self) -> None:
        for device in list_available_devices("bt"):
            key = ("bt", device)
            assert key in DEVICE_REGISTRY, (
                f"BT device '{device}' has profile directory but no DEVICE_REGISTRY entry"
            )

    def test_registry_factories_are_callable(self) -> None:
        """All registered factories must be callable (real)."""
        for key, entry in DEVICE_REGISTRY.items():
            ef = entry["exploiter_factory"]
            duf = entry["device_utils_factory"]
            assert callable(ef), f"{key} exploiter_factory is not callable"
            assert callable(duf), f"{key} device_utils_factory is not callable"


# ── get_active_device fallback ────────────────────────────────────────────────


class TestGetActiveDevice:
    def test_returns_tuple(self) -> None:
        result = get_active_device()
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_fallback_values(self, tmp_path, monkeypatch) -> None:
        """When active_device.json is absent, fallback is ("mediatek", "fiveg")."""
        import device_profile as dp

        monkeypatch.setattr(dp, "_ACTIVE_DEVICE_PATH", str(tmp_path / "missing.json"))
        device, protocol = dp.get_active_device()
        assert device == "mediatek"
        assert protocol == "fiveg"

    def test_reads_from_file(self, tmp_path, monkeypatch) -> None:
        import device_profile as dp

        active_file = tmp_path / "active_device.json"
        active_file.write_text(json.dumps({"device": "unisoc_ud710", "protocol": "fiveg"}))
        monkeypatch.setattr(dp, "_ACTIVE_DEVICE_PATH", str(active_file))
        device, protocol = dp.get_active_device()
        assert device == "unisoc_ud710"
        assert protocol == "fiveg"


# ── All profiles: bulk validity check ────────────────────────────────────────


class TestAllProfilesValid:
    def test_all_modem_profiles_load(self) -> None:
        for device in list_available_devices("fiveg"):
            p = load_device_profile(device, "fiveg")
            assert p.vendor
            assert p.device
            assert p.protocol

    def test_all_modem_profiles_have_required_fields(self) -> None:
        agent_path = os.path.join(os.path.dirname(__file__), "..")
        for device in list_available_devices("fiveg"):
            profile_json = os.path.join(
                agent_path, "data", "devices", "fiveg", device, "profile.json"
            )
            with open(profile_json) as f:
                data = json.load(f)
            for field in FIVEG_REQUIRED_FIELDS:
                assert field in data, (
                    f"Modem profile '{device}' missing required field '{field}'"
                )

    def test_all_bt_profiles_have_required_fields(self) -> None:
        agent_path = os.path.join(os.path.dirname(__file__), "..")
        for device in list_available_devices("bt"):
            profile_json = os.path.join(
                agent_path, "data", "devices", "bt", device, "profile.json"
            )
            with open(profile_json) as f:
                data = json.load(f)
            for field in BT_REQUIRED_FIELDS:
                assert field in data, (
                    f"BT profile '{device}' missing required field '{field}'"
                )


# ── _patch_bluetooth_configs: mandatory value enforcement ─────────────────────


class TestPatchBluetoothConfigs:
    """Tests for the BT config patcher's mandatory-field enforcement."""

    # Keys we enforce and their required values.
    REQUIRED = {
        "BridgeHCI": True,
        "InterceptTX": True,
        "LMPSniffing": True,
        "RXBypassOnDemand": False,
    }
    # Keys that must be left untouched.
    TUNABLE = ["DisableRoleSwitch", "RXBypass"]

    def _make_bt_config(self, tmp_path, overrides: dict | None = None) -> str:
        """Write a minimal bt_config.json under tmp_path and return its path."""
        cfg = {
            "config": {
                "Bluetooth": {
                    "BridgeHCI": True,
                    "InterceptTX": True,
                    "LMPSniffing": True,
                    "RXBypassOnDemand": False,
                    "DisableRoleSwitch": False,
                    "RXBypass": False,
                    "TargetBDAddress": "00:00:00:00:00:00",
                }
            }
        }
        if overrides:
            cfg["config"]["Bluetooth"].update(overrides)
        p = tmp_path / "bt_config.json"
        p.write_text(json.dumps(cfg))
        return str(p)

    def _make_bt_profile(self, address: str = "24:0a:c4:61:1c:1a") -> BtProfile:
        """Build a minimal BtProfile without touching the real profile directory."""
        import device_profile as dp

        common = dict(
            vendor="Espressif",
            device="ESP32",
            protocol="bt",
            header_offset=0,
            capture_filename="capture.pcapng",
            exploit_prefix="",
            exploit_folder_name="bt_exploits",
            log_subdir="bt",
            crash_oracle={},
            role_description="BT researcher",
            web_search_examples=["ESP32 CVE"],
            profile_dir="/tmp",
            known_crashes_path="/tmp/known.json",
            crash_signatures_path="/tmp/sigs.json",
            normal_capture="/tmp/normal.pcapng",
            fuzz_capture="/tmp/fuzz.pcapng",
            exploit_folder="/tmp/exploits",
            log_subdir_path="/tmp/logs",
            prompt_crash_knowledge="",
            prompt_strategy_hints="",
            prompt_research_hints="",
        )
        return BtProfile(**common, target_address=address)

    def test_mandatory_fields_enforced_when_wrong(self, tmp_path, caplog):
        """Each mandatory field is corrected when its value deviates."""
        import logging

        import device_profile as dp

        # Set every mandatory field to the wrong value.
        bad_values = {
            "BridgeHCI": False,
            "InterceptTX": False,
            "LMPSniffing": False,
            "RXBypassOnDemand": True,
        }
        config_path = self._make_bt_config(tmp_path, overrides=bad_values)
        profile = self._make_bt_profile()

        original = dp.BT_WD_SM_CONFIG if hasattr(dp, "BT_WD_SM_CONFIG") else None
        # Redirect the patcher to our temp file only.
        import unittest.mock as mock

        with (
            mock.patch("device_profile._patch_bluetooth_configs.__code__", None)
            if False
            else mock.patch("builtins.open", side_effect=open)
        ):
            pass  # real open

        log = logging.getLogger("test_mandatory")
        with caplog.at_level(logging.WARNING, logger="test_mandatory"):
            # Call the private function directly with our temp path.
            _call_patcher_with_path(profile, log, config_path)

        # Read back and verify all mandatory fields were corrected.
        with open(config_path) as f:
            result = json.load(f)
        bt = result["config"]["Bluetooth"]
        for key, expected in self.REQUIRED.items():
            assert bt[key] == expected, f"{key} was not corrected"

    def test_warning_logged_for_each_bad_field(self, tmp_path):
        """A warning is logged for every field that required correction."""
        import logging

        bad_values = {"BridgeHCI": False, "RXBypassOnDemand": True}
        config_path = self._make_bt_config(tmp_path, overrides=bad_values)
        profile = self._make_bt_profile()

        warnings = []

        class CapturingLogger(logging.Logger):
            def warning(self, msg, *args, **kwargs):
                warnings.append(msg)

        log = CapturingLogger("capturing")
        _call_patcher_with_path(profile, log, config_path)

        # Should have one warning per bad field.
        assert len(warnings) == len(bad_values)
        assert any("BridgeHCI" in w for w in warnings)
        assert any("RXBypassOnDemand" in w for w in warnings)

    def test_tunable_fields_left_unchanged(self, tmp_path):
        """DisableRoleSwitch and RXBypass must not be touched by the patcher."""
        config_path = self._make_bt_config(
            tmp_path,
            overrides={"DisableRoleSwitch": True, "RXBypass": True},
        )
        profile = self._make_bt_profile()
        import logging

        _call_patcher_with_path(profile, logging.getLogger("test"), config_path)

        with open(config_path) as f:
            result = json.load(f)
        bt = result["config"]["Bluetooth"]
        assert bt["DisableRoleSwitch"] is True, (
            "DisableRoleSwitch was incorrectly reset"
        )
        assert bt["RXBypass"] is True, "RXBypass was incorrectly reset"

    def test_target_address_patched(self, tmp_path):
        """TargetBDAddress is still updated from the profile."""
        config_path = self._make_bt_config(tmp_path)
        profile = self._make_bt_profile(address="aa:bb:cc:dd:ee:ff")
        import logging

        _call_patcher_with_path(profile, logging.getLogger("test"), config_path)

        with open(config_path) as f:
            result = json.load(f)
        assert result["config"]["Bluetooth"]["TargetBDAddress"] == "aa:bb:cc:dd:ee:ff"

    def test_correct_values_unchanged_after_patch(self, tmp_path):
        """If all values are already correct, the patcher must not alter their values.

        Note: the patcher may still write the file (e.g. to update TargetBDAddress),
        but the mandatory fields must remain at their required values.
        """
        config_path = self._make_bt_config(tmp_path)
        profile = self._make_bt_profile(address="24:0a:c4:61:1c:1a")
        import logging

        _call_patcher_with_path(profile, logging.getLogger("test"), config_path)

        with open(config_path) as f:
            result = json.load(f)
        bt = result["config"]["Bluetooth"]
        for key, expected in self.REQUIRED.items():
            assert bt[key] == expected, f"{key} changed to unexpected value after patch"


def _call_patcher_with_path(profile: BtProfile, log, config_path: str) -> None:
    """Invoke _patch_bluetooth_configs but redirect it to a single specific config path.

    We monkey-patch the two path constants so only our temp file is touched,
    avoiding any side effects on the real bt_config.json.
    """
    import unittest.mock as mock

    import device_profile as dp

    # The function reads BT_WD_SM_CONFIG and the bindings path.  Override both
    # to point to our temp file so the real config is untouched.
    with mock.patch.object(dp, "_WDISSECTOR_PATH", os.path.dirname(config_path)):
        # Also patch the constants import so BT_WD_SM_CONFIG resolves to our file.
        with mock.patch.dict(
            "sys.modules",
            {"constants": mock.MagicMock(BT_WD_SM_CONFIG=config_path)},
        ):
            dp._patch_bluetooth_configs(profile, log)


class TestPatchModemConfigsLteBs:
    """Verify ENABLE_LTE_BS patch behavior for 5G & global configs."""

    def test_enable_lte_bs_false_patches_configs(self, tmp_path):
        import logging
        from unittest.mock import patch
        import device_profile as dp

        fiveg_cfg = tmp_path / "configs" / "5gnr_gnb_config.json"
        global_cfg = tmp_path / "configs" / "global_config.json"
        fiveg_cfg.parent.mkdir(parents=True, exist_ok=True)

        fiveg_content = {
            "config": {
                "Monitor": {"ActiveMonitorTypes": [1], "ADB": {}},
                "NR5G": {"AutoStartCoreNetwork": False, "AutoStartBaseStation": False},
            }
        }
        global_content = {
            "config": {
                "Services": {
                    "UEModemManager": {"EnableADB": False, "AutoReconnectModem": False}
                }
            }
        }
        fiveg_cfg.write_text(json.dumps(fiveg_content))
        global_cfg.write_text(json.dumps(global_content))

        profile = dp.load_device_profile("mediatek", "fiveg")

        with patch.object(dp, "_WDISSECTOR_PATH", str(tmp_path)):
            with patch("constants.ENABLE_LTE_BS", False):
                dp._patch_modem_configs(profile, logging.getLogger("test"))

        res_fiveg = json.loads(fiveg_cfg.read_text())["config"]["NR5G"]
        res_global = json.loads(global_cfg.read_text())["config"]["Services"]["UEModemManager"]

        assert res_fiveg["AutoStartCoreNetwork"] is True
        assert res_fiveg["AutoStartBaseStation"] is True
        assert res_global["AutoReconnectModem"] is True

    def test_enable_lte_bs_true_patches_configs(self, tmp_path):
        import logging
        from unittest.mock import patch
        import device_profile as dp

        fiveg_cfg = tmp_path / "configs" / "5gnr_gnb_config.json"
        global_cfg = tmp_path / "configs" / "global_config.json"
        fiveg_cfg.parent.mkdir(parents=True, exist_ok=True)

        fiveg_content = {
            "config": {
                "Monitor": {"ActiveMonitorTypes": [1], "ADB": {}},
                "NR5G": {"AutoStartCoreNetwork": True, "AutoStartBaseStation": False},
            }
        }
        global_content = {
            "config": {
                "Services": {
                    "UEModemManager": {"EnableADB": False, "AutoReconnectModem": True}
                }
            }
        }
        fiveg_cfg.write_text(json.dumps(fiveg_content))
        global_cfg.write_text(json.dumps(global_content))

        profile = dp.load_device_profile("mediatek", "fiveg")

        with patch.object(dp, "_WDISSECTOR_PATH", str(tmp_path)):
            with patch("constants.ENABLE_LTE_BS", True):
                dp._patch_modem_configs(profile, logging.getLogger("test"))

        res_fiveg = json.loads(fiveg_cfg.read_text())["config"]["NR5G"]
        res_global = json.loads(global_cfg.read_text())["config"]["Services"]["UEModemManager"]

        assert res_fiveg["AutoStartCoreNetwork"] is False
        assert res_fiveg["AutoStartBaseStation"] is True
        assert res_global["AutoReconnectModem"] is False


