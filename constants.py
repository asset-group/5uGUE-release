import os
import re
import socket

# LLM API config — secrets imported from secret_keys.py (gitignored)
from secret_keys import (
    AZURE_API_KEY,
    AZURE_BASE_URL,
    OPENROUTER_API_KEY,
    OPENROUTER_BASE_URL,
    TAVILY_API_KEY,
)

_THIS_DIR = os.path.dirname(os.path.abspath(__file__))
# Default WDISSECTOR_PATH to the wdissector root two levels above this module
# (<root>/modules/<agent>); override with WDISSECTOR_PATH if running elsewhere.
WDISSECTOR_PATH = os.environ.get("WDISSECTOR_PATH") or os.path.dirname(os.path.dirname(_THIS_DIR))
# Default AGENT_PATH to the directory this module lives in, so the agent works
# regardless of what the checkout is named. Override with AGENT_PATH.
AGENT_PATH = os.environ.get("AGENT_PATH") or _THIS_DIR

WEB_SEARCH_PROVIDER = "tavily"

# Per-host namespacing for logs / sweeps / kb so multiple workers can sync into a
# single master without colliding. HOST_ID defaults to socket.gethostname();
# AGENT_HOST_ID env override exists for cloned VMs or friendlier aliases.
HOST_ID = os.environ.get("AGENT_HOST_ID") or socket.gethostname()
if not re.fullmatch(r"[A-Za-z0-9._-]+", HOST_ID):
    raise ValueError(
        f"Invalid AGENT_HOST_ID/hostname: {HOST_ID!r} "
        f"(must match [A-Za-z0-9._-]+ — used in filesystem paths and rsync destinations)"
    )

# DEPRECATED: Use profile.exploit_folder from device_profile.py instead.
# Kept only as fallback default for backward compatibility.
EXPLOIT_FOLDER = f"{WDISSECTOR_PATH}/modules/exploits/5gnr_gnb"
AGENT_GENERATED_CRASHES = f"{AGENT_PATH}/agent_generated_crashes"
AGENT_GENERATED_TESTS = f"{AGENT_PATH}/agent_generated_tests"

# *_ROOT = host-agnostic aggregation root (master walks <ROOT>/* across hosts).
# *_PATH = host-scoped writer path (this machine writes here).
LOG_ROOT = f"{AGENT_PATH}/logs"
KB_ROOT = f"{AGENT_PATH}/kb"
RUNTIME_LOG_ROOT = f"{AGENT_PATH}/runtime_logs"
REPORTS_ROOT = f"{AGENT_PATH}/reports"

LOG_PATH = f"{LOG_ROOT}/{HOST_ID}"
KB_PATH = f"{KB_ROOT}/{HOST_ID}"
RUN_LOG_PATH = LOG_PATH  # alias, used by upstream.utils.misc.setup_logging
RUNTIME_LOG_PATH = f"{RUNTIME_LOG_ROOT}/{HOST_ID}"
REPORTS_PATH = f"{REPORTS_ROOT}/{HOST_ID}"

# WDissector tool paths
TSHARK_PATH = f"{WDISSECTOR_PATH}/bin/tshark"
EDITCAP_PATH = f"{WDISSECTOR_PATH}/bin/editcap"
ADB_PATH = f"{WDISSECTOR_PATH}/3rd-party/adb/adb"
UHUBCTL_PATH = f"{WDISSECTOR_PATH}/3rd-party/uhubctl/uhubctls"
# DEPRECATED: Use profile.adb_serial from device_profile.py (ModemProfile) instead.
ADB_DEVICE_SERIAL = "STUB_ADB_SERIAL"
ADB_CMD_TIMEOUT = 10  # seconds per command
CAPTURE_CACHE_PATH = f"{AGENT_PATH}/cache"

# WDissector config paths
BT_WD_SM_CONFIG = f"{WDISSECTOR_PATH}/configs/bt_config.json"
BT_WD_MODEL_CONFIG = f"{WDISSECTOR_PATH}/configs/models/bt/sdp_rfcomm_query.json"
FIVEG_WD_SM_CONFIG = f"{WDISSECTOR_PATH}/configs/5gnr_gnb_config.json"
FIVEG_WD_MODEL_CONFIG = f"{WDISSECTOR_PATH}/configs/models/5gnr_gnb/nr-softmodem.json"
WIFI_WD_SM_CONFIG = f"{WDISSECTOR_PATH}/configs/wifi_ap_config.json"
WIFI_WD_MODEL_CONFIG = f"{WDISSECTOR_PATH}/configs/models/wifi_ap/wpa2_eap.json"

# DEPRECATED: Use profile.normal_capture / profile.fuzz_capture from device_profile.py instead.
NORMAL_CAPTURE = f"{AGENT_PATH}/data/captures/normal/capture_nr5g_gnb.pcapng"
FUZZ_CAPTURE = f"{AGENT_PATH}/data/captures/fuzz/capture_nr5g_gnb.pcapng"

# Glossary and template (local copies)
FIVEG_FIELDS_DESC = f"{AGENT_PATH}/data/glossary/fiveg_fields_desc.json"
EXPLOIT_TEMPLATE = f"{AGENT_PATH}/data/exploit.template"
# DEPRECATED: Use profile.known_crashes_path / profile.crash_signatures_path instead.
KNOWN_CRASHES = f"{AGENT_PATH}/data/known_crashes.json"
KNOWN_CRASH_SIGNATURES = f"{AGENT_PATH}/data/known_crash_signatures.json"

# Device profiles root directory (data/devices/<device_type>/<device_id>/)
DEVICES_PATH = f"{AGENT_PATH}/data/devices"
# DEPRECATED: Use DEVICES_PATH. Kept for any legacy scripts that still reference it.
MODEMS_PATH = f"{AGENT_PATH}/data/modems"

MODEL = os.environ.get("MODEL", "anthropic/claude-sonnet-4.6")

# LLM provider gate: resolves which (api_key, base_url) pair feeds the OpenAI client.
# When LLM_PROVIDER=azure, MODEL must be the Azure deployment name, not a slugged ID.
LLM_PROVIDER = os.environ.get("LLM_PROVIDER", "openrouter").lower()

if LLM_PROVIDER == "openrouter":
    LLM_API_KEY = OPENROUTER_API_KEY
    LLM_BASE_URL = OPENROUTER_BASE_URL
elif LLM_PROVIDER == "azure":
    LLM_API_KEY = AZURE_API_KEY
    LLM_BASE_URL = AZURE_BASE_URL
else:
    raise ValueError(
        f"Unknown LLM_PROVIDER={LLM_PROVIDER!r} (expected 'openrouter' or 'azure')"
    )
MAX_TOKENS = 8192
SUMMARIZE_THRESHOLD_LARGE = 200_000  # token threshold for V3/FULL
SUMMARIZE_THRESHOLD_DEFAULT = 50_000  # token threshold for other versions
BATCH_TOOL_RESULT_MAX_CHARS = 30_000  # higher char limit for execute_test_batch results
SKIP_EXPLOIT_CLEANUP = False  # Set True to keep exploit files between runs
ENABLE_LTE_BS = False  # Enable LTE base station (True) vs auto-started by lte_fuzzer (False)


CRASHES_CSV = f"{AGENT_PATH}/crashes.csv"

# Crash classification categories
CRASH_PUBLICLY_KNOWN = "publicly_known_crash"
CRASH_NON_PUBLICLY_KNOWN = "non_publicly_known_crash"
CRASH_FULLY_NOVEL = "fully_novel_crash"

# Web research / vulnerability cache
VULN_CACHE_PATH = f"{AGENT_PATH}/data/vuln_cache"
# Global KB is shared across hosts — lives directly under KB_ROOT, not under
# the per-host KB_PATH, so workers and master see the same global knowledge.
GLOBAL_KB_PATH = os.path.join(KB_ROOT, "global")

# Paper storage paths
PAPERS_PATH = f"{AGENT_PATH}/data/papers"
PAPERS_PDF_PATH = f"{AGENT_PATH}/data/papers/pdfs"
PAPERS_TEXT_PATH = f"{AGENT_PATH}/data/papers/text"
PAPERS_INDEX_PATH = f"{AGENT_PATH}/data/papers/index.jsonl"
LOCAL_PAPERS_PATH = f"{AGENT_PATH}/5g-papers-main"

os.makedirs(LOG_PATH, exist_ok=True)
os.makedirs(KB_PATH, exist_ok=True)
os.makedirs(CAPTURE_CACHE_PATH, exist_ok=True)
os.makedirs(RUNTIME_LOG_PATH, exist_ok=True)
os.makedirs(REPORTS_PATH, exist_ok=True)
os.makedirs(VULN_CACHE_PATH, exist_ok=True)
os.makedirs(GLOBAL_KB_PATH, exist_ok=True)
os.makedirs(AGENT_GENERATED_CRASHES, exist_ok=True)
os.makedirs(AGENT_GENERATED_TESTS, exist_ok=True)
os.makedirs(PAPERS_PATH, exist_ok=True)
os.makedirs(PAPERS_PDF_PATH, exist_ok=True)
os.makedirs(PAPERS_TEXT_PATH, exist_ok=True)
