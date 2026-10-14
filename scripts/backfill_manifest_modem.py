#!/usr/bin/env python3
"""One-time migration: add "modem": "mediatek" to all existing manifests missing the field."""

import glob
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(SCRIPT_DIR)
RUNTIME_LOG_ROOT = os.path.join(AGENT_DIR, "runtime_logs")


def backfill():
    # Walk both host-namespaced (post-migration) and flat (legacy) layouts.
    manifests = sorted(
        set(
            glob.glob(os.path.join(RUNTIME_LOG_ROOT, "*", "*_manifest.json"))
            + glob.glob(os.path.join(RUNTIME_LOG_ROOT, "*_manifest.json"))
        )
    )
    updated = 0
    for path in manifests:
        with open(path) as f:
            data = json.load(f)
        if "modem" not in data:
            data["modem"] = "mediatek"
            with open(path, "w") as f:
                json.dump(data, f, indent=2)
            updated += 1
    print(f"Backfilled {updated}/{len(manifests)} manifests with modem=mediatek")


if __name__ == "__main__":
    backfill()
