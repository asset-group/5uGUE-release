"""Tests for Bluetooth Classic (ESP32) target support in the fuzzer module."""

import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from device_profile import (
    DEVICE_REGISTRY,
    BtProfile,
    get_device_utils,
    get_exploiter,
    load_device_profile,
)
from upstream.utils.target_device.esp32_bt import BluetoothUtils
from upstream.utils.wd_utils import WDissectorTool

# ── Registry and Profile tests ───────────────────────────────────────────────


class TestBluetoothRegistry:
    def test_registry_has_esp32(self) -> None:
        assert ("bt", "esp32") in DEVICE_REGISTRY
        factories = DEVICE_REGISTRY[("bt", "esp32")]
        assert callable(factories["exploiter_factory"])
        assert callable(factories["device_utils_factory"])

    def test_get_exploiter_instantiates_esp32_bt(self) -> None:
        profile = load_device_profile("esp32", "bt")
        wd_tool = MagicMock()

        # Mock esp32_bt.py initialization to prevent actual serial/system checks
        with patch(
            "upstream.exploiter.esp32_bt.ESP32BtExploiter.__init__", return_value=None
        ) as mock_init:
            exploiter = get_exploiter(
                "esp32",
                "bt",
                profile,
                wd_tool,
                run_dir="/tmp",
                target_port="/dev/ttyUSB2",
                host_port="/dev/ttyUSB1",
                target_hub_port=1,
                exploit_timeout=45,
            )
            mock_init.assert_called_once_with(
                run_dir="/tmp",
                target="24:0a:c4:61:1c:1a",
                target_port="/dev/ttyUSB2",
                target_hub_port=1,
                host_port="/dev/ttyUSB1",
                exploit_timeout=45,
                wd_tool=wd_tool,
                log_subdir="Bluetooth",
                capture_filename="capture_bluetooth.pcapng",
                monitor_log="monitor.1.txt",
            )

    @patch(
        "upstream.utils.target_device.esp32_bt.BluetoothUtils.prep_reference_packets"
    )
    def test_get_device_utils_instantiates_bluetooth_utils(self, mock_prep) -> None:
        profile = load_device_profile("esp32", "bt")
        with patch("upstream.utils.wd_utils.get_wd_tool") as mock_get_wd:
            utils = get_device_utils("esp32", "bt", profile)
            assert isinstance(utils, BluetoothUtils)
            assert utils.monitor_log == "monitor.1.txt"
            assert utils.default_pcap_name == "capture_bluetooth.pcapng"


# ── BluetoothUtils tests ─────────────────────────────────────────────────────


class TestBluetoothUtils:
    @pytest.fixture
    def mock_wd_tool(self):
        return MagicMock()

    @pytest.fixture
    def bluetooth_utils(self, mock_wd_tool):
        with patch(
            "upstream.utils.target_device.esp32_bt.BluetoothUtils.prep_reference_packets"
        ):
            return BluetoothUtils(
                ref_packets_paths=[],
                crash_signatures_path=None,
                monitor_log="bt_monitor.log",
                wd_tool=mock_wd_tool,
                capture_filename="capture_bluetooth.pcapng",
            )

    def test_load_signatures_missing_path(self, bluetooth_utils) -> None:
        sigs = bluetooth_utils._load_known_signatures(None)
        assert sigs == {"public": [], "non_public": []}

        sigs = bluetooth_utils._load_known_signatures("/nonexistent/file.json")
        assert sigs == {"public": [], "non_public": []}

    def test_load_signatures_valid_dict(self, bluetooth_utils, tmp_path) -> None:
        sig_file = tmp_path / "signatures.json"
        data = {"public": ["hci error"], "non_public": ["Assert failed at line 100"]}
        sig_file.write_text(json.dumps(data))

        sigs = bluetooth_utils._load_known_signatures(str(sig_file))
        assert sigs == data

    def test_load_signatures_legacy_list(self, bluetooth_utils, tmp_path) -> None:
        sig_file = tmp_path / "signatures.json"
        data = ["assert fail", "hci crash"]
        sig_file.write_text(json.dumps(data))

        sigs = bluetooth_utils._load_known_signatures(str(sig_file))
        assert sigs == {"public": [], "non_public": data}

    def test_classify_crash(self, bluetooth_utils) -> None:
        from constants import (
            CRASH_FULLY_NOVEL,
            CRASH_NON_PUBLICLY_KNOWN,
            CRASH_PUBLICLY_KNOWN,
        )

        bluetooth_utils.known_signatures_public = ["HCI Error 0x12"]
        bluetooth_utils.known_signatures_non_public = ["assert failed in main.c"]

        assert (
            bluetooth_utils.classify_crash("Some info | HCI Error 0x12 | dump")
            == CRASH_PUBLICLY_KNOWN
        )
        assert (
            bluetooth_utils.classify_crash("assert failed in main.c")
            == CRASH_NON_PUBLICLY_KNOWN
        )
        assert (
            bluetooth_utils.classify_crash("some unknown crash info")
            == CRASH_FULLY_NOVEL
        )

    def test_crash_ids_from_trace_log(self, bluetooth_utils, tmp_path) -> None:
        log_file = tmp_path / "bt_monitor.log"
        log_content = (
            "[2026-06-26 12:00:00.100] Send flooding packet now\n"
            "[2026-06-26 12:00:01.000] assert failed: lc_task.c line 405\n"
            "[2026-06-26 12:00:01.500] Guru Meditation Error: Core 0 panic'ed\n"
            "[2026-06-26 12:00:02.100] Backtrace:0x40028dcc 0x4001a637\n"
            "[2026-06-26 12:00:10.000] Guru Meditation Error: Core 0 panic'ed (LoadProhibited)\n"
        )
        log_file.write_text(log_content)

        crashes = bluetooth_utils.crash_ids_from_trace_log(str(log_file))
        assert len(crashes) >= 1
        # The first crash should group assert and panic if within time window
        first_crash_id, first_ts = crashes[0]
        assert "assert failed: lc_task.c line 405" in first_crash_id
        assert "Guru Meditation Error" in first_crash_id
        assert "Backtrace" in first_crash_id

    def test_check_crash_no_log_file(self, bluetooth_utils, tmp_path) -> None:
        # Pass directory without the monitor log file
        crashes, category = bluetooth_utils.check_crash(str(tmp_path))
        assert crashes == []
        assert category == ""

    def test_check_crash_with_log_file(self, bluetooth_utils, tmp_path) -> None:
        from constants import CRASH_PUBLICLY_KNOWN

        log_file = tmp_path / "bt_monitor.log"
        log_content = (
            "[2026-06-26 12:00:00.000] Guru Meditation Error: Core 0 panic'ed\n"
        )
        log_file.write_text(log_content)

        bluetooth_utils.known_signatures_public = ["Guru Meditation Error"]
        crashes, category = bluetooth_utils.check_crash(str(tmp_path))
        assert len(crashes) == 1
        assert category == CRASH_PUBLICLY_KNOWN


# ── WDissectorTool Alias mapping tests ────────────────────────────────────────


class TestWDissectorToolAlias:
    def test_bt_and_bluetooth_initialization(self) -> None:
        with (
            patch("wdissector.Machine.init", return_value=True),
            patch("wdissector.Machine.LoadModel", return_value=True),
            patch("wdissector.WDPacketLabelGenerator.init", return_value=True),
        ):
            # Test "bt" protocol
            tool_bluetooth = WDissectorTool("bt", 0)
            assert tool_bluetooth.protocol == "bt"

            # Test "bt" protocol
            tool_bt = WDissectorTool("bt", 0)
            assert tool_bt.protocol == "bt"
