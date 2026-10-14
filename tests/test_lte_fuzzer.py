"""Test that bin/lte_fuzzer starts without compilation or loading errors."""

import json
import os
import subprocess
from unittest.mock import MagicMock

import pytest

from constants import WDISSECTOR_PATH

LTE_FUZZER = os.path.join(WDISSECTOR_PATH, "bin", "lte_fuzzer")
FIVEG_CONFIG = os.path.join(WDISSECTOR_PATH, "configs", "5gnr_gnb_config.json")
GLOBAL_CONFIG = os.path.join(WDISSECTOR_PATH, "configs", "global_config.json")
FIVEG_CONFIG_BINDINGS = os.path.join(
    WDISSECTOR_PATH, "bindings", "python", "configs", "5gnr_gnb_config.json"
)
GLOBAL_CONFIG_BINDINGS = os.path.join(
    WDISSECTOR_PATH, "bindings", "python", "configs", "global_config.json"
)


class TestLteFuzzerExploit:
    def test_exploit_empty_loads_modules_successfully(self):
        """Run lte_fuzzer --exploit= and verify it exits cleanly with all modules loaded."""
        result = subprocess.run(
            [LTE_FUZZER, "--exploit="],
            cwd=WDISSECTOR_PATH,
            capture_output=True,
            text=True,
            timeout=120,
        )
        combined = result.stdout + result.stderr
        assert result.returncode == 0, (
            f"lte_fuzzer exited with code {result.returncode}\n{combined}"
        )
        assert "Modules Compiled / Loaded" in combined, (
            f"Module loading message not found in output:\n{combined}"
        )
        # Verify ALL .cpp files compiled — the count before "/" must match total after "/"
        import re

        m = re.search(
            r"\[Modules\]\s+(\d+)/(\d+)\s+Modules Compiled / Loaded", combined
        )
        assert m, f"Could not parse module count from output:\n{combined}"
        compiled, total = int(m.group(1)), int(m.group(2))
        assert compiled == total, (
            f"Only {compiled}/{total} modules compiled successfully.\n{combined}"
        )

    def test_exploit_empty_no_crash_or_error(self):
        """Ensure no segfault, abort, or fatal error messages appear."""
        result = subprocess.run(
            [LTE_FUZZER, "--exploit="],
            cwd=WDISSECTOR_PATH,
            capture_output=True,
            text=True,
            timeout=120,
        )
        combined = (result.stdout + result.stderr).lower()
        for bad_signal in [
            "segmentation fault",
            "aborted",
            "fatal error",
            "core dumped",
            "failed to compile",
        ]:
            assert bad_signal not in combined, (
                f"Unexpected error '{bad_signal}' in output"
            )


class TestWDissectorExploiterFolder:
    """Verify that WDissectorExploiter sets exploit_folder to match lte_fuzzer's path."""

    def test_fiveg_exploit_folder_matches_lte_fuzzer(self):
        """fiveg exploit_folder must be modules/exploits/5gnr_gnb to match lte_fuzzer."""
        from upstream.exploiter.wdissector_exploiter import WDissectorExploiter

        exploiter = WDissectorExploiter(
            protocol="fiveg",
            board="oneplus",
            run_dir=WDISSECTOR_PATH,
            wd_tool=MagicMock(),
        )
        expected = f"{WDISSECTOR_PATH}/modules/exploits/5gnr_gnb"
        assert exploiter.exploit_folder == expected, (
            f"Expected {expected}, got {exploiter.exploit_folder}"
        )

    def test_fiveg_exploit_folder_matches_constants(self):
        """EXPLOIT_FOLDER in constants.py must match the path lte_fuzzer uses."""
        from constants import EXPLOIT_FOLDER

        expected = f"{WDISSECTOR_PATH}/modules/exploits/5gnr_gnb"
        assert EXPLOIT_FOLDER == expected, (
            f"EXPLOIT_FOLDER ({EXPLOIT_FOLDER}) doesn't match lte_fuzzer path ({expected})"
        )

    def test_bt_uses_bluetooth_path(self):
        """For bt protocol, exploit_folder should use the bluetooth path."""
        from upstream.exploiter.wdissector_exploiter import WDissectorExploiter

        exploiter = WDissectorExploiter(
            protocol="bt",
            board="oneplus",
            run_dir=WDISSECTOR_PATH,
            wd_tool=MagicMock(),
        )
        expected = f"{WDISSECTOR_PATH}/modules/exploits/bluetooth"
        assert exploiter.exploit_folder == expected

    def test_wifi_uses_wifi_ap_path(self):
        """For wifi protocol, exploit_folder should use the wifi_ap path."""
        from upstream.exploiter.wdissector_exploiter import WDissectorExploiter

        exploiter = WDissectorExploiter(
            protocol="wifi",
            board="oneplus",
            run_dir=WDISSECTOR_PATH,
            wd_tool=MagicMock(),
        )
        expected = f"{WDISSECTOR_PATH}/modules/exploits/wifi_ap"
        assert exploiter.exploit_folder == expected


class TestFiveGConfig:
    """Verify critical settings in 5gnr_gnb_config.json."""

    @pytest.fixture(autouse=True)
    def load_config(self):
        with open(FIVEG_CONFIG) as f:
            self.config = json.load(f)["config"]

    def test_monitor_enabled(self):
        """Monitor must be enabled for crash detection to work."""
        assert self.config["Monitor"]["Enable"] is True

    def test_active_monitor_type_valid(self):
        """ActiveMonitorTypes must reference a valid index in MonitorsTypeList."""
        monitor_types = self.config["Monitor"]["MonitorsTypeList"]
        active = self.config["Monitor"]["ActiveMonitorTypes"]
        assert isinstance(active, list) and len(active) > 0
        for idx in active:
            assert 0 <= idx < len(monitor_types), (
                f"ActiveMonitorTypes index {idx} out of range for "
                f"MonitorsTypeList (length {len(monitor_types)})"
            )


class TestGlobalConfig:
    """Verify critical settings in global_config.json."""

    @pytest.fixture(autouse=True)
    def load_config(self):
        with open(GLOBAL_CONFIG) as f:
            self.config = json.load(f)

    def test_reports_sender_disabled(self):
        """ReportsSender must be disabled to prevent unintended report uploads."""
        assert self.config["config"]["Services"]["ReportsSender"]["Enable"] is False

    def test_enable_adb_matches_modem(self, modem_profile):
        """EnableADB must be false for modems without ADB."""
        enable_adb = self.config["config"]["Services"]["UEModemManager"]["EnableADB"]
        has_adb = bool(modem_profile.adb_serial)
        assert enable_adb == has_adb, (
            f"EnableADB is {enable_adb} but modem '{modem_profile.device}' "
            f"{'has' if has_adb else 'has no'} ADB serial"
        )

    def test_adb_device_matches_modem(self, modem_profile):
        """ADBDevice must match the active modem profile's serial when ADB is in use."""
        if not modem_profile.adb_serial:
            pytest.skip("Modem has no ADB serial")
        adb_device = self.config["config"]["Services"]["UEModemManager"]["ADBDevice"]
        assert adb_device == modem_profile.adb_serial, (
            f"ADBDevice is '{adb_device}' but profile '{modem_profile.device}' "
            f"expects '{modem_profile.adb_serial}'"
        )


class TestConfigCopiesInSync:
    """Both configs/ and bindings/python/configs/ copies must agree on ADB settings.

    run_agent.py patches both on every run; if the bindings copy drifts, the
    Open5GS / UEModemManager runtime calls adb against the wrong device.
    """

    @pytest.fixture(autouse=True)
    def _require_bindings_copy(self):
        if not os.path.isfile(GLOBAL_CONFIG_BINDINGS):
            pytest.skip(f"No bindings config at {GLOBAL_CONFIG_BINDINGS}")

    def test_global_config_adb_device_in_sync(self, modem_profile):
        if not modem_profile.adb_serial:
            pytest.skip("Modem has no ADB serial")
        with open(GLOBAL_CONFIG) as f:
            primary = json.load(f)["config"]["Services"]["UEModemManager"]["ADBDevice"]
        with open(GLOBAL_CONFIG_BINDINGS) as f:
            bindings = json.load(f)["config"]["Services"]["UEModemManager"]["ADBDevice"]
        assert primary == bindings == modem_profile.adb_serial, (
            f"ADBDevice mismatch: primary='{primary}', bindings='{bindings}', "
            f"profile='{modem_profile.adb_serial}'"
        )

    def test_global_config_enable_adb_in_sync(self, modem_profile):
        with open(GLOBAL_CONFIG) as f:
            primary = json.load(f)["config"]["Services"]["UEModemManager"]["EnableADB"]
        with open(GLOBAL_CONFIG_BINDINGS) as f:
            bindings = json.load(f)["config"]["Services"]["UEModemManager"]["EnableADB"]
        assert primary == bindings == bool(modem_profile.adb_serial), (
            f"EnableADB mismatch: primary={primary}, bindings={bindings}, "
            f"profile expects {bool(modem_profile.adb_serial)}"
        )

    def test_fiveg_monitor_adb_device_in_sync(self, modem_profile):
        """Monitor.ADB.ADBDevice in 5gnr_gnb_config.json drives the runtime
        `adb -s ...` connection (and Open5GS shares that session). Both copies
        must match the active modem's serial."""
        if not os.path.isfile(FIVEG_CONFIG_BINDINGS):
            pytest.skip(f"No bindings 5G config at {FIVEG_CONFIG_BINDINGS}")
        if not modem_profile.adb_serial:
            pytest.skip("Modem has no ADB serial")
        with open(FIVEG_CONFIG) as f:
            primary = json.load(f)["config"]["Monitor"].get("ADB", {}).get("ADBDevice")
        with open(FIVEG_CONFIG_BINDINGS) as f:
            bindings = json.load(f)["config"]["Monitor"].get("ADB", {}).get("ADBDevice")
        assert primary == bindings == modem_profile.adb_serial, (
            f"Monitor.ADB.ADBDevice mismatch: primary='{primary}', bindings='{bindings}', "
            f"profile expects '{modem_profile.adb_serial}'"
        )

    def test_fiveg_active_monitor_in_sync(self, modem_profile):
        if not os.path.isfile(FIVEG_CONFIG_BINDINGS):
            pytest.skip(f"No bindings 5G config at {FIVEG_CONFIG_BINDINGS}")
        expected = modem_profile.crash_oracle.get("active_monitor_type")
        if expected is None:
            pytest.skip("Profile has no active_monitor_type")
        with open(FIVEG_CONFIG) as f:
            primary = json.load(f)["config"]["Monitor"]["ActiveMonitorTypes"]
        with open(FIVEG_CONFIG_BINDINGS) as f:
            bindings = json.load(f)["config"]["Monitor"]["ActiveMonitorTypes"]
        assert primary == bindings == [expected], (
            f"ActiveMonitorTypes mismatch: primary={primary}, bindings={bindings}, "
            f"profile expects [{expected}]"
        )

    def test_fiveg_adb_magic_words_match_profile(self, modem_profile):
        """ADBMagicWords in both 5G config copies must match the profile's
        effective list (override or DEFAULT_ADB_MAGIC_WORDS) — WDissector's
        MonitorADB thread reads this list to detect crashes in logcat."""
        if not os.path.isfile(FIVEG_CONFIG_BINDINGS):
            pytest.skip(f"No bindings 5G config at {FIVEG_CONFIG_BINDINGS}")
        from device_profile import (
            DEFAULT_ADB_MAGIC_WORDS,
            FivegProfile,
            patch_device_configs,
        )

        if not isinstance(modem_profile, FivegProfile):
            pytest.skip("Active device is not a modem — skipping ADB magic words test")

        # Apply the same patch run_agent.py would, so the assertion is
        # deterministic regardless of what the last run left on disk.
        patch_device_configs(modem_profile)
        expected = modem_profile.crash_oracle.get(
            "adb_magic_words", DEFAULT_ADB_MAGIC_WORDS
        )
        with open(FIVEG_CONFIG) as f:
            primary = json.load(f)["config"]["Monitor"]["ADB"]["ADBMagicWords"]
        with open(FIVEG_CONFIG_BINDINGS) as f:
            bindings = json.load(f)["config"]["Monitor"]["ADB"]["ADBMagicWords"]
        assert primary == bindings == expected, (
            f"ADBMagicWords mismatch: primary={primary}, bindings={bindings}, "
            f"profile expects {expected}"
        )
