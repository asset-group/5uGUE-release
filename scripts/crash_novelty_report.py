#!/usr/bin/env python3
"""Classify crash_ids in crashes.csv against known_crash_signatures.json
and report counts of publicly known, non-publicly known, and fully novel crashes."""

import csv
import json
import os
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_PATH = os.path.dirname(SCRIPT_DIR)

CRASHES_CSV = os.path.join(AGENT_PATH, "crashes.csv")
SIGNATURES_JSON = os.path.join(AGENT_PATH, "data", "known_crash_signatures.json")


def classify_crash(
    crash_id: str, public_sigs: list[str], non_public_sigs: list[str]
) -> str:
    for sig in public_sigs:
        if sig in crash_id or crash_id in sig:
            return "publicly_known_crash"
    for sig in non_public_sigs:
        if sig in crash_id or crash_id in sig:
            return "non_publicly_known_crash"
    return "fully_novel_crash"


def main():
    with open(SIGNATURES_JSON) as f:
        sigs = json.load(f)
    public_sigs = sigs["public"]
    non_public_sigs = sigs["non_public"]

    counts = {
        "publicly_known_crash": 0,
        "non_publicly_known_crash": 0,
        "fully_novel_crash": 0,
    }
    unique_ids = {
        "publicly_known_crash": set(),
        "non_publicly_known_crash": set(),
        "fully_novel_crash": set(),
    }

    with open(CRASHES_CSV) as f:
        reader = csv.DictReader(f)
        total = 0
        for row in reader:
            crash_id = row["crash_id"].strip()
            if not crash_id:
                continue
            total += 1
            category = classify_crash(crash_id, public_sigs, non_public_sigs)
            counts[category] += 1
            unique_ids[category].add(crash_id)

    print(f"Total crashes: {total}")
    print(f"Unique crash_ids: {sum(len(v) for v in unique_ids.values())}")
    print()
    print(f"{'Category':<30} {'Crashes':>8} {'Unique IDs':>12}")
    print("-" * 52)
    for cat, label in [
        ("publicly_known_crash", "Publicly known"),
        ("non_publicly_known_crash", "Non-publicly known"),
        ("fully_novel_crash", "Fully novel"),
    ]:
        print(f"{label:<30} {counts[cat]:>8} {len(unique_ids[cat]):>12}")

    if unique_ids["fully_novel_crash"]:
        print(
            f"\n--- Fully novel crash IDs ({len(unique_ids['fully_novel_crash'])}) ---"
        )
        for cid in sorted(unique_ids["fully_novel_crash"]):
            print(f"  {cid}")

    if unique_ids["non_publicly_known_crash"]:
        print(
            f"\n--- Non-publicly known crash IDs ({len(unique_ids['non_publicly_known_crash'])}) ---"
        )
        for cid in sorted(unique_ids["non_publicly_known_crash"]):
            print(f"  {cid}")


if __name__ == "__main__":
    main()
