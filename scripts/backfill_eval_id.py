#!/usr/bin/env python3
"""Backfill eval_id into existing eval CSVs and the evaluation table.

For each `reports/<host>/eval_*.csv`:
  - If the CSV header is missing `eval_id`: generate one uuid4().hex,
    prepend the column to the header, write it into every row.
  - If `eval_id` is already present: read the value (warn if rows
    disagree) and proceed to the DB step anyway — the previous run may
    have stamped the CSV but failed before updating Postgres.
  - For each row's run_id, run:
        UPDATE evaluation SET eval_id = %s
        WHERE run_id = %s AND eval_id IS NULL
    This is idempotent: re-running a fully-backfilled CSV is a no-op.

Usage:
    python scripts/backfill_eval_id.py                 # backfill all CSVs
    python scripts/backfill_eval_id.py --dry-run       # report only, no PG_DSN needed
    python scripts/backfill_eval_id.py --csv <path>    # single file
"""

from __future__ import annotations

import argparse
import csv
import glob
import os
import shutil
import sys
import tempfile
import uuid

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
AGENT_DIR = os.path.dirname(SCRIPT_DIR)
REPORTS_ROOT = os.path.join(AGENT_DIR, "reports")


def _list_csvs() -> list[str]:
    return sorted(
        glob.glob(os.path.join(REPORTS_ROOT, "*", "eval_*.csv"))
        + glob.glob(os.path.join(REPORTS_ROOT, "eval_*.csv"))
    )


def _read_csv(path: str) -> tuple[list[str], list[dict]]:
    with open(path, newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = list(reader.fieldnames or [])
        rows = list(reader)
    return fieldnames, rows


def _write_csv_atomic(path: str, fieldnames: list[str], rows: list[dict]) -> None:
    """Write to a sibling tempfile + os.replace so partial writes can't
    corrupt the source CSV."""
    fd, tmp_path = tempfile.mkstemp(
        prefix=os.path.basename(path) + ".",
        suffix=".tmp",
        dir=os.path.dirname(path),
    )
    try:
        with os.fdopen(fd, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)
        raise


def _stamp_csv(path: str, dry_run: bool) -> tuple[str | None, list[str], bool]:
    """Ensure the CSV has a single eval_id across all rows. Return
    (eval_id, run_ids, csv_was_modified). Returns (None, [], False) on
    skip (e.g. mismatched eval_ids across rows)."""
    fieldnames, rows = _read_csv(path)
    if not rows:
        print(f"  [skip] {path} — no rows")
        return None, [], False

    run_ids = [r.get("run_id", "").strip() for r in rows]
    run_ids = [r for r in run_ids if r and r != "N/A"]

    if "eval_id" in fieldnames:
        existing = {r.get("eval_id", "").strip() for r in rows}
        existing.discard("")
        if len(existing) > 1:
            print(f"  [warn] {path} — multiple eval_id values {existing}; skipping")
            return None, [], False
        if not existing:
            # Column present but every row blank — treat like missing.
            eval_id = uuid.uuid4().hex
            for r in rows:
                r["eval_id"] = eval_id
            if not dry_run:
                _write_csv_atomic(path, fieldnames, rows)
            print(
                f"  [stamp] {path} → eval_id={eval_id} (column present, values blank)"
            )
            return eval_id, run_ids, True
        eval_id = next(iter(existing))
        return eval_id, run_ids, False

    eval_id = uuid.uuid4().hex
    new_fieldnames = ["eval_id"] + fieldnames
    for r in rows:
        r["eval_id"] = eval_id
    if not dry_run:
        _write_csv_atomic(path, new_fieldnames, rows)
    print(f"  [stamp] {path} → eval_id={eval_id}")
    return eval_id, run_ids, True


def _update_db(rows: list[tuple[str, list[str]]]) -> tuple[int, int]:
    """rows = [(eval_id, [run_id, ...]), ...]. Returns (updated, missing)."""
    sys.path.insert(0, AGENT_DIR)
    from dashboard.db import get_pool

    updated = 0
    missing = 0
    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            for eval_id, run_ids in rows:
                for run_id in run_ids:
                    cur.execute(
                        "UPDATE evaluation SET eval_id = %s "
                        "WHERE run_id = %s AND eval_id IS NULL",
                        (eval_id, run_id),
                    )
                    if cur.rowcount == 1:
                        updated += 1
                    elif cur.rowcount == 0:
                        # Row already has an eval_id, or doesn't exist yet.
                        cur.execute(
                            "SELECT eval_id FROM evaluation WHERE run_id = %s",
                            (run_id,),
                        )
                        row = cur.fetchone()
                        if row is None:
                            missing += 1
        conn.commit()
    return updated, missing


def _backfill_db_only(dry_run: bool) -> int:
    """Group existing `evaluation` rows by source_csv_path and stamp one
    eval_id per group — no filesystem access. Useful when running on the
    storage server, where worker CSVs were never rsynced (only the DB rows
    were ingested).

    Rows where source_csv_path is NULL stay NULL — we have no grouping
    signal for them.
    """
    sys.path.insert(0, AGENT_DIR)
    from dashboard.db import get_pool

    with get_pool().connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT source_csv_path, count(*) AS n
                FROM evaluation
                WHERE eval_id IS NULL AND source_csv_path IS NOT NULL
                GROUP BY source_csv_path
                ORDER BY source_csv_path
                """,
            )
            groups = list(cur.fetchall())

            if not groups:
                print("No NULL eval_id rows with a source_csv_path. Nothing to do.")
                cur.execute(
                    "SELECT count(*) AS n FROM evaluation "
                    "WHERE eval_id IS NULL AND source_csv_path IS NULL"
                )
                orphans = cur.fetchone()["n"]
                if orphans:
                    print(
                        f"WARN: {orphans} rows have NULL eval_id AND NULL source_csv_path — "
                        "no grouping key available, leaving as-is"
                    )
                return 0

            print(f"Found {len(groups)} CSV path group(s) needing eval_id:")
            total_updated = 0
            for g in groups:
                csv_path = g["source_csv_path"]
                eval_id = uuid.uuid4().hex
                action = "[dry-run]" if dry_run else "[stamp]"
                print(f"  {action} {csv_path} ({g['n']} rows) → eval_id={eval_id}")
                if not dry_run:
                    cur.execute(
                        "UPDATE evaluation SET eval_id = %s "
                        "WHERE eval_id IS NULL AND source_csv_path = %s",
                        (eval_id, csv_path),
                    )
                    total_updated += cur.rowcount

            if not dry_run:
                conn.commit()
                cur.execute(
                    "SELECT count(*) AS n FROM evaluation WHERE eval_id IS NULL"
                )
                remaining = cur.fetchone()["n"]
                print(
                    f"\nUpdated {total_updated} rows. {remaining} rows still NULL on eval_id."
                )
            else:
                print("\n[dry-run] no DB writes")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report intended changes; no CSV writes, no DB writes",
    )
    parser.add_argument(
        "--csv",
        default=None,
        help="Single CSV path to process (default: all reports/<host>/eval_*.csv)",
    )
    parser.add_argument(
        "--db-only",
        action="store_true",
        help="Skip the filesystem; group existing DB rows by source_csv_path "
        "and stamp one eval_id per group. Use this on the storage server "
        "to fix rows from workers whose CSVs were never rsynced.",
    )
    args = parser.parse_args()

    if args.db_only:
        if args.csv:
            print("ERROR: --csv and --db-only are mutually exclusive", file=sys.stderr)
            return 2
        if not args.dry_run and not os.environ.get("PG_DSN"):
            print(
                "ERROR: PG_DSN must be set for non-dry-run --db-only mode",
                file=sys.stderr,
            )
            return 2
        return _backfill_db_only(dry_run=args.dry_run)

    if args.csv:
        targets = [os.path.abspath(args.csv)]
    else:
        targets = _list_csvs()

    if not targets:
        print("No eval CSVs found.")
        return 0

    print(f"Processing {len(targets)} CSV(s)...")

    db_payload: list[tuple[str, list[str]]] = []
    csvs_modified = 0
    csvs_already_stamped = 0
    csvs_skipped = 0

    for path in targets:
        eval_id, run_ids, modified = _stamp_csv(path, dry_run=args.dry_run)
        if eval_id is None:
            csvs_skipped += 1
            continue
        if modified:
            csvs_modified += 1
        else:
            csvs_already_stamped += 1
        db_payload.append((eval_id, run_ids))

    print()
    print(
        f"CSV summary: {csvs_modified} stamped, "
        f"{csvs_already_stamped} already had eval_id, {csvs_skipped} skipped"
    )

    if args.dry_run:
        print("[dry-run] skipping DB updates")
        return 0

    if not os.environ.get("PG_DSN"):
        print(
            "ERROR: PG_DSN must be set for non-dry-run mode "
            "(re-run with --dry-run for filesystem-only inspection)",
            file=sys.stderr,
        )
        return 2

    print("Updating evaluation table...")
    updated, missing = _update_db(db_payload)
    print(
        f"DB summary: {updated} rows updated, {missing} run_ids missing from evaluation table"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
