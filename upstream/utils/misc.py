import hashlib
import logging
import os
import signal
import subprocess
import time
from datetime import datetime
from functools import lru_cache, wraps
from logging.config import dictConfig
from typing import Literal

from constants import RUN_LOG_PATH, UHUBCTL_PATH

logger = logging.getLogger(__name__)


def restart_usb_device(hub_loc: str, hub_port: int):
    """Power-cycle a USB device via uhubctl."""
    cmd = f"{UHUBCTL_PATH} -a cycle -l {hub_loc} -p {hub_port}"
    logger.debug(f"Restarting USB device: {cmd}")
    subprocess.run(cmd, shell=True, stdout=subprocess.PIPE)
    time.sleep(5)


def clean_up_process(proc_name_keyword: str, sig=signal.SIGKILL):
    """Kill processes whose name contains given keyword."""
    try:
        pids = (
            subprocess.check_output(["pgrep", "-f", proc_name_keyword])
            .decode()
            .strip()
            .split("\n")
        )
        pids = [int(pid) for pid in pids]
        for pid in pids:
            try:
                os.kill(pid, sig)
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass  # process already exited
            except Exception:
                logger.error("clean_up_process", exc_info=True)
        time.sleep(2)
    except Exception:
        pass


LogLevel = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

# Timestamp shared across a single process lifetime
_run_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")


def setup_logging(level: LogLevel):
    log_file = os.path.join(RUN_LOG_PATH, f"app_{_run_timestamp}.log")
    logging_config = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {
            "default": {
                "format": "%(asctime)s [%(levelname)s] %(filename)s:%(lineno)d: %(message)s"
            }
        },
        "handlers": {
            "file": {
                "class": "logging.FileHandler",
                "filename": log_file,
                "level": level,
                "formatter": "default",
            },
            "console": {
                "class": "logging.StreamHandler",
                "level": level,
                "formatter": "default",
                "stream": "ext://sys.stdout",
            },
        },
        "root": {
            "handlers": ["file", "console"],
            "level": level,
        },
    }
    dictConfig(logging_config)
    return log_file


def calc_bytes_sha256(b: bytes) -> str:
    """Calculate sha256 hash value of a bytes object."""
    hash_sha256 = hashlib.sha256()
    hash_sha256.update(b)
    return hash_sha256.hexdigest()


def bytes_to_cpp_array(b: bytes):
    """Convert Python bytes to a C++ array literal."""
    pkt_string = ",".join([hex(i) for i in b])
    return f"{{ {pkt_string} }}"


def cached(func):
    """Apply an LRU cache to a function while preserving its signature."""
    cached_func = lru_cache()(func)
    return wraps(func)(cached_func)
