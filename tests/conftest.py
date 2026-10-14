"""Shared fixtures for agentic-fuzz tests."""

import os
import sys

import pytest

# Bootstrap sys.path so constants.py (and WDissector bin/) are importable.
# Derive paths from this file's location to avoid hardcoding.
_CONFTEST_DIR = os.path.dirname(os.path.abspath(__file__))
_AGENT_PATH = os.path.dirname(_CONFTEST_DIR)
_WDISSECTOR_PATH = os.path.dirname(os.path.dirname(_AGENT_PATH))

if _AGENT_PATH not in sys.path:
    sys.path.insert(0, _AGENT_PATH)
if os.path.join(_WDISSECTOR_PATH, "bin") not in sys.path:
    sys.path.insert(1, os.path.join(_WDISSECTOR_PATH, "bin"))

# WDissector needs to run from repo root
os.chdir(_WDISSECTOR_PATH)

# Now that sys.path is set up, import the canonical constants
from constants import WDISSECTOR_PATH, AGENT_PATH


def pytest_addoption(parser):
    from device_profile import get_active_device

    _default_device, _default_protocol = get_active_device()
    parser.addoption(
        "--device",
        action="store",
        default=_default_device,
        help="Device profile ID for tests (default: from data/active_device.json)",
    )
    parser.addoption(
        "--protocol",
        action="store",
        default=_default_protocol,
        choices=["fiveg", "bt", "wifi"],
        help="Protocol for tests (default: from data/active_device.json)",
    )


@pytest.fixture(scope="session")
def wdissector_path():
    return WDISSECTOR_PATH


@pytest.fixture(scope="session")
def agent_path():
    return AGENT_PATH


@pytest.fixture(scope="session")
def normal_capture():
    from constants import NORMAL_CAPTURE

    return NORMAL_CAPTURE


@pytest.fixture(scope="session")
def fuzz_capture():
    from constants import FUZZ_CAPTURE

    return FUZZ_CAPTURE


@pytest.fixture(scope="session")
def wd_tool(request):
    """Cached WDissectorTool instance (expensive — session-scoped)."""
    from upstream.utils.wd_utils import WDissectorTool
    protocol = request.config.getoption("--protocol")
    offset = 4 if protocol == "bt" else 0
    return WDissectorTool(protocol, offset)


@pytest.fixture(scope="session")
def td_utils(request, normal_capture, fuzz_capture, wd_tool):
    """Device-utils instance with reference packets loaded."""
    from device_profile import load_device_profile, get_device_utils
    device = request.config.getoption("--device")
    protocol = request.config.getoption("--protocol")
    profile = load_device_profile(device, protocol)
    return get_device_utils(device, protocol, profile, wd_tool=wd_tool)


@pytest.fixture(scope="session")
def device_profile(request):
    """Load the device profile specified by --device / --protocol."""
    from device_profile import load_device_profile

    device = request.config.getoption("--device")
    protocol = request.config.getoption("--protocol")
    return load_device_profile(device, protocol)


@pytest.fixture(scope="session")
def modem_profile(request):
    """Load a modem profile. Alias for device_profile when protocol='fiveg'.

    Tests that specifically test modem behaviour (ADB, etc.) should use this
    fixture and guard with isinstance(modem_profile, FivegProfile) where needed.
    """
    from device_profile import load_device_profile

    device = request.config.getoption("--device")
    protocol = request.config.getoption("--protocol")
    return load_device_profile(device, protocol)
