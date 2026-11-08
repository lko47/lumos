"""Headless command-line entry point for the initial database workflows."""

from __future__ import annotations

import argparse
import sqlite3
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .core.database import DatabaseError, check_database, initialize_database


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lumos",
        description="Terminal network mapping built on the user's installed Nmap.",
    )
    parser.add_argument("--version", action="version", version=f"lumos {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)

    db = commands.add_parser("db", help="create or validate an engagement database")
    db_commands = db.add_subparsers(dest="db_command", required=True)
    init = db_commands.add_parser("init", help="create a new owner-only database")
    init.add_argument("path", type=Path, help="database file to create (must not exist)")
    init.add_argument("--name", required=True, help="engagement name")
    check = db_commands.add_parser("check", help="check database schema and integrity")
    check.add_argument("path", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "db" and args.db_command == "init":
            engagement_id = initialize_database(args.path, args.name)
            print(f"Created {args.path} (engagement {engagement_id})")
            return 0
        if args.command == "db" and args.db_command == "check":
            result = check_database(args.path)
            print(
                f"Valid Lumos database: schema {result['user_version']}; "
                f"{result['tables']} tables; {result['views']} views; "
                f"integrity {result['integrity']}"
            )
            return 0
    except (DatabaseError, OSError, sqlite3.Error) as exc:
        print(f"lumos: error: {exc}", file=sys.stderr)
        return 2
    parser.error("unsupported command")
    return 2
