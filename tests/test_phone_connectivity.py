"""Test that the UE phone is connected and reachable via ADB.

Skipped automatically when the active modem profile has no ADB serial.
"""

import os
import subprocess

import pytest

from constants import ADB_PATH as ADB


@pytest.fixture(autouse=True)
def _require_adb(modem_profile):
    """Skip the entire test if the modem profile has no ADB serial."""
    if not modem_profile.adb_serial:
        pytest.skip(
            f"Modem '{modem_profile.device}' has no ADB — skipping phone connectivity tests"
        )


class TestPhoneConnectivity:
    def test_adb_binary_exists(self):
        assert os.path.isfile(ADB), f"ADB binary not found at {ADB}"
        assert os.access(ADB, os.X_OK), f"ADB binary at {ADB} is not executable"

    def test_adb_devices_lists_phone(self, modem_profile):
        serial = modem_profile.adb_serial
        result = subprocess.run(
            [ADB, "devices"], capture_output=True, text=True, timeout=10
        )
        assert result.returncode == 0, f"adb devices failed: {result.stderr}"
        assert serial in result.stdout, (
            f"Expected device {serial} not found in:\n{result.stdout}"
        )

    def test_phone_is_authorized(self, modem_profile):
        """Device should show 'device' status, not 'unauthorized' or 'offline'."""
        serial = modem_profile.adb_serial
        result = subprocess.run(
            [ADB, "devices"], capture_output=True, text=True, timeout=10
        )
        for line in result.stdout.strip().splitlines():
            if serial in line:
                assert "device" in line and "unauthorized" not in line, (
                    f"Phone is not authorized: {line}"
                )
                return
        pytest.fail(f"Device {serial} not found in adb devices output")

    def test_adb_shell_works(self, modem_profile):
        """Can execute a basic command on the phone."""
        serial = modem_profile.adb_serial
        result = subprocess.run(
            [ADB, "-s", serial, "shell", "echo", "ping"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, f"adb shell failed: {result.stderr}"
        assert "ping" in result.stdout

    def test_logcat_accessible(self, modem_profile):
        """ADB logcat should be readable (needed for crash monitoring)."""
        serial = modem_profile.adb_serial
        result = subprocess.run(
            [ADB, "-s", serial, "logcat", "-d", "-t", "5"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, f"logcat failed: {result.stderr}"

    def test_airplane_mode_readable(self, modem_profile):
        """Can read airplane mode state (WDissector toggles this during tests)."""
        serial = modem_profile.adb_serial
        result = subprocess.run(
            [
                ADB,
                "-s",
                serial,
                "shell",
                "settings",
                "get",
                "global",
                "airplane_mode_on",
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0
        val = result.stdout.strip()
        assert val in ("0", "1"), f"Unexpected airplane_mode_on value: {val}"
