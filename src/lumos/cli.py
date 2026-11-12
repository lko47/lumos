"""Headless CLI for engagement databases, scope, scans, imports, and reports."""

from __future__ import annotations

import argparse
import json
import shlex
import sqlite3
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Sequence

from . import __version__
from .core.database import DatabaseError, check_database, initialize_database, open_database
from .core.nmap.iflist import discover_interfaces
from .core.nmap.runner import NmapRunnerError
from .core.reports import write_markdown_report
from .core.scanning import ScopeConfirmationRequired, scan_database
from .core.scan_store import ScanStoreError
from .core.vantage_store import save_interfaces
from .core.scope_store import add_scope_rule
from .core.xml_import import import_nmap_xml

AUTHORIZED_USE_NOTICE = "Authorized use only: scan systems and networks you own or are explicitly permitted to assess. Confirm scope and permissions before proceeding."


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

    scope = commands.add_parser("scope", help="manage the engagement's scan scope")
    scope_commands = scope.add_subparsers(dest="scope_command", required=True)
    scope_add = scope_commands.add_parser("add", help="add a CIDR, IP, range, or exact hostname scope rule")
    scope_add.add_argument("database", type=Path)
    scope_add.add_argument("target")
    scope_add.add_argument("--network", required=True, help="named network for address grouping (scope rule applies engagement-wide)")
    scope_add.add_argument("--exclude", action="store_true", help="add an exclusion instead of an allow rule")
    scope_add.add_argument("--author", default="")
    scope_show = scope_commands.add_parser("show", help="list scope rules")
    scope_show.add_argument("database", type=Path)

    interfaces = commands.add_parser(
        "interfaces", help="show scanner interfaces and routes from Nmap --iflist"
    )
    interfaces.add_argument(
        "database",
        nargs="?",
        type=Path,
        help="engagement database (required with --save)",
    )
    interfaces.add_argument("--nmap", dest="nmap_executable", help="explicit Nmap executable path")
    interfaces.add_argument("--json", action="store_true", help="print structured JSON")
    interfaces.add_argument(
        "--save",
        action="store_true",
        help="record the discovered interfaces on the engagement vantage point",
    )

    scan = commands.add_parser("scan", help="run a scope-checked scan using the installed Nmap")
    scan.add_argument("database", type=Path)
    scan.add_argument("targets", nargs="+", help="IP, CIDR, range, or exactly allowlisted hostname")
    scan.add_argument("--network", required=True, help="named network to associate with observations")
    scan.add_argument("--nmap-options", default="", help="Nmap option text (no shell; targets remain scope-checked)")
    scan.add_argument("--nmap", dest="nmap_executable", help="explicit Nmap executable path")
    scan.add_argument("--interface", default="", help="select Nmap network interface")
    scan.add_argument("--operator", default=None)
    scan.add_argument("--confirm-scope", default="", help="exact typed phrase shown for an out-of-scope override")
    scan.add_argument("--no-evidence", action="store_true", help="do not retain compressed raw XML evidence")
    scan.add_argument("--yes", action="store_true", help="confirm the displayed Nmap command without a prompt")

    xml_import = commands.add_parser("import", help="import Nmap XML into a named network")
    xml_import.add_argument("database", type=Path)
    xml_import.add_argument("xml_file", type=Path)
    xml_import.add_argument("--network", required=True)
    xml_import.add_argument("--operator", default=None)
    xml_import.add_argument("--no-evidence", action="store_true")

    tui = commands.add_parser("tui", help="open the interactive map (plain output when redirected)")
    tui.add_argument("database", type=Path, help="engagement database")

    report = commands.add_parser("report", help="generate engagement reports")
    report_commands = report.add_subparsers(dest="report_format", required=True)
    markdown = report_commands.add_parser("markdown", help="write a Markdown report")
    markdown.add_argument("database", type=Path)
    markdown.add_argument("output", type=Path)
    return parser


def _show_command(argv: Sequence[str], *, label: str, yes: bool) -> None:
    print(f"{label}: {shlex.join(list(argv))}", file=sys.stderr)
    if yes:
        return
    if not sys.stdin.isatty():
        raise ValueError("Non-interactive scan requires --yes after reviewing the displayed command")
    answer = input("Run this Nmap command? [y/N] ").strip().lower()
    if answer not in {"y", "yes"}:
        raise ValueError("Scan cancelled before Nmap was started")


def _scope_show(path: Path) -> int:
    conn = open_database(path, readonly=True)
    try:
        rows = conn.execute(
            "SELECT included, rule_kind, rule_value, author, created_at "
            "FROM scope_rules ORDER BY included DESC, rule_kind, rule_value"
        )
        count = 0
        for row in rows:
            count += 1
            print(f"{'IN' if row[0] else 'EXCLUDE'} [engagement-wide] {row[1]} {row[2]} (author={row[3] or '-'}, created={row[4]})")
        if not count:
            print("No scope rules recorded.")
        return 0
    finally:
        conn.close()


def main(argv: Sequence[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "interfaces":
            snapshot = discover_interfaces(args.nmap_executable)
            if args.json:
                print(
                    json.dumps(
                        {
                            "interfaces": [asdict(item) for item in snapshot.interfaces],
                            "routes": [asdict(item) for item in snapshot.routes],
                        },
                        ensure_ascii=False,
                        sort_keys=True,
                        indent=2,
                    )
                )
            else:
                print("Interfaces:")
                if not snapshot.interfaces:
                    print("  (none)")
                for item in snapshot.interfaces:
                    state = "up" if item.is_up else "down"
                    address = item.address or "no address"
                    mac = f"; MAC {item.mac}" if item.mac else ""
                    print(
                        f"  {item.name} ({item.short_name}) {item.interface_type} {state}; "
                        f"MTU {item.mtu}; {address}{mac}"
                    )
                print("Routes:")
                if not snapshot.routes:
                    print("  (none)")
                for item in snapshot.routes:
                    gateway = f" via {item.gateway}" if item.gateway else ""
                    print(
                        f"  {item.destination} dev {item.device}{gateway} "
                        f"(metric {item.metric})"
                    )
            if args.save:
                if args.database is None:
                    raise ValueError("--save requires an engagement database path")
                vantage_id, saved = save_interfaces(args.database, snapshot)
                print(f"Saved {saved} interface(s) to vantage point {vantage_id[:8]}")
            return 0
        if args.command == "db" and args.db_command == "init":
            engagement_id = initialize_database(args.path, args.name)
            print(AUTHORIZED_USE_NOTICE, file=sys.stderr)
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
        if args.command == "scope" and args.scope_command == "add":
            network_id, inserted = add_scope_rule(
                args.database, args.network, args.target, included=not args.exclude, author=args.author
            )
            print(f"{'Added' if inserted else 'Already present'} {'include' if not args.exclude else 'exclude'} rule in network {args.network!r} ({network_id})")
            return 0
        if args.command == "scope" and args.scope_command == "show":
            return _scope_show(args.database)
        if args.command == "scan":
            print(AUTHORIZED_USE_NOTICE, file=sys.stderr)
            outcome = scan_database(
                args.database,
                args.network,
                args.targets,
                nmap_options=args.nmap_options,
                interface=args.interface,
                operator=args.operator,
                executable=args.nmap_executable,
                evidence=not args.no_evidence,
                scope_confirmation=args.confirm_scope,
                on_command=lambda command: _show_command(
                    command,
                    label="Nmap command",
                    yes=args.yes,
                ),
                on_progress=lambda text: print(text, end="", file=sys.stderr, flush=True),
            )
            status = "cancelled" if outcome.result.cancelled else "completed" if outcome.result.exit_code == 0 and not outcome.result.parse_error else "failed"
            print(f"Scan {outcome.scan_id}: {status}; {outcome.result.hosts_seen} host(s); exit {outcome.result.exit_code}")
            if outcome.result.parse_error:
                print(f"XML parser: {outcome.result.parse_error}", file=sys.stderr)
            if outcome.result.stderr:
                print(outcome.result.stderr, file=sys.stderr)
            return 0 if status == "completed" else 1
        if args.command == "import":
            scan_id, hosts, parse_error = import_nmap_xml(
                args.database,
                args.network,
                args.xml_file,
                operator=args.operator,
                evidence=not args.no_evidence,
            )
            status = "partial/failed" if parse_error else "completed"
            print(f"XML import {scan_id}: {status}; {hosts} host(s)")
            if parse_error:
                print(parse_error, file=sys.stderr)
                return 1
            return 0
        if args.command == "tui":
            from .tui.app import run_tui

            return run_tui(args.database)
        if args.command == "report" and args.report_format == "markdown":
            write_markdown_report(args.database, args.output)
            print(f"Wrote Markdown report to {args.output}")
            return 0
    except ScopeConfirmationRequired as exc:
        print(f"lumos: blocked: {exc}", file=sys.stderr)
        print(f"Re-run with --confirm-scope {shlex.quote(exc.confirmation_text)}", file=sys.stderr)
        return 2
    except (DatabaseError, NmapRunnerError, ScanStoreError, OSError, sqlite3.Error, ValueError) as exc:
        print(f"lumos: error: {exc}", file=sys.stderr)
        return 2
    parser.error("unsupported command")
    return 2
