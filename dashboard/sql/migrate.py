#!/usr/bin/env python3
"""Apply pending dashboard/sql/*.sql files against the configured Postgres.

Migrations are plain SQL — no Alembic, no DSL. Each file runs once,
in lexical order, and is recorded in the `schema_migration` table so
re-running the script is a no-op.

Usage:
    python dashboard/sql/migrate.py                 # uses $PG_DSN
    python dashboard/sql/migrate.py --dsn postgres://...
"""

import argparse
import os
import sys

import psycopg

SQL_DIR = os.path.dirname(os.path.abspath(__file__))


def _list_migrations() -> list[str]:
    return sorted(f for f in os.listdir(SQL_DIR) if f.endswith(".sql"))


def _ensure_migration_table(conn: psycopg.Connection) -> None:
    with conn.cursor() as cur:
        cur.execute(
            "CREATE TABLE IF NOT EXISTS schema_migration ("
            "filename text PRIMARY KEY, "
            "applied_at timestamptz NOT NULL DEFAULT now())"
        )
    conn.commit()


def _applied(conn: psycopg.Connection) -> set[str]:
    with conn.cursor() as cur:
        cur.execute("SELECT filename FROM schema_migration")
        return {row[0] for row in cur.fetchall()}


def apply(dsn: str) -> list[str]:
    """Apply pending migrations. Returns the list of filenames applied."""
    applied: list[str] = []
    with psycopg.connect(dsn) as conn:
        _ensure_migration_table(conn)
        already = _applied(conn)
        for filename in _list_migrations():
            if filename in already:
                continue
            path = os.path.join(SQL_DIR, filename)
            with open(path) as f:
                sql = f.read()
            with conn.cursor() as cur:
                cur.execute(sql)
                cur.execute(
                    "INSERT INTO schema_migration (filename) VALUES (%s) "
                    "ON CONFLICT (filename) DO NOTHING",
                    (filename,),
                )
            conn.commit()
            applied.append(filename)
            print(f"[migrate] applied {filename}")
    return applied


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--dsn",
        default=os.environ.get("PG_DSN"),
        help="Postgres DSN (default: $PG_DSN)",
    )
    args = parser.parse_args()
    if not args.dsn:
        print("ERROR: --dsn or $PG_DSN required", file=sys.stderr)
        sys.exit(2)
    applied = apply(args.dsn)
    if not applied:
        print("[migrate] up to date — no migrations applied")


if __name__ == "__main__":
    main()
