"""Headless CLI for engagement databases, scope, scans, imports, and reports."""

from __future__ import annotations

import argparse
import json
import os
import shlex
import sqlite3
import sys
from dataclasses import asdict
from pathlib import Path
from typing import Sequence

from . import __version__
from .core import engine_scan
from .core.inference import rebuild_inferred
from .core.merge import MergeError, merge_engagement
from .core.database import (
    DatabaseError,
    check_database,
    initialize_database,
    open_database,
    upgrade_database,
)
from .core.nmap.iflist import discover_interfaces
from .core.nmap.runner import NmapRunnerError
from .core.reports import write_markdown_report, write_svg_report
from .core.scanning import ScopeConfirmationRequired, scan_database
from .core.scan_store import ScanStoreError
from .core.vantage_store import save_interfaces
from .core.scope import read_target_file
from .core.scope_store import add_scope_rule
from .core.xml_import import import_nmap_xml
from .services import actions, compare, demo, notes, queue, review, sanitize, tags
from .core import state as local_state

AUTHORIZED_USE_NOTICE = "Authorized use only: scan systems and networks you own or are explicitly permitted to assess. Confirm scope and permissions before proceeding."


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="lumos",
        description="Terminal network mapping built on the user's installed Nmap.",
    )
    parser.add_argument("--version", action="version", version=f"lumos {__version__}")
    commands = parser.add_subparsers(dest="command")

    db = commands.add_parser("db", help="create or validate an engagement database")
    db_commands = db.add_subparsers(dest="db_command", required=True)
    init = db_commands.add_parser("init", help="create a new owner-only database")
    init.add_argument("path", type=Path, help="database file to create (must not exist)")
    init.add_argument("--name", required=True, help="engagement name")
    check = db_commands.add_parser("check", help="check database schema and integrity")
    check.add_argument("path", type=Path)
    upgrade = db_commands.add_parser("upgrade", help="apply forward-only schema migrations in place")
    upgrade.add_argument("path", type=Path)
    merge = db_commands.add_parser(
        "merge", help="merge another copy of this engagement into a database"
    )
    merge.add_argument("target", type=Path)
    merge.add_argument("source", type=Path)
    merge.add_argument("--operator", default="")
    merge.add_argument("--dry-run", action="store_true", help="count what would be copied, change nothing")
    rebuild = db_commands.add_parser(
        "rebuild", help="derive inferred segment hubs and links from stored facts"
    )
    rebuild.add_argument("path", type=Path)
    rebuild.add_argument("--json", action="store_true", help="print the result as JSON")

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
    scan.add_argument("targets", nargs="*", help="IP, CIDR, range, or exactly allowlisted hostname")
    scan.add_argument("--target-file", type=Path, default=None,
                      help="read targets from a file; every line is scope-checked")
    scan.add_argument("--network", required=True, help="named network to associate with observations")
    scan.add_argument("--nmap-options", default="", help="Nmap option text (no shell; targets remain scope-checked)")
    scan.add_argument("--nmap", dest="nmap_executable", help="explicit Nmap executable path")
    scan.add_argument("--interface", default="", help="select Nmap network interface")
    scan.add_argument("--operator", default=None)
    scan.add_argument("--confirm-scope", default="", help="exact typed phrase shown for an out-of-scope override")
    scan.add_argument("--no-evidence", action="store_true", help="do not retain compressed raw XML evidence")
    scan.add_argument("--yes", action="store_true", help="confirm the displayed Nmap command without a prompt")
    scan.add_argument(
        "--engine", default="nmap",
        help=(
            "enumerator: nmap (default), masscan, naabu or rustscan; "
            "masscan needs raw-socket privileges, naabu/rustscan report ports only"
        ),
    )
    scan.add_argument("--engine-ports", default="", help="port list for a non-Nmap engine")
    scan.add_argument("--engine-rate", type=int, default=1000, help="packets/second for a non-Nmap engine")

    xml_import = commands.add_parser("import", help="import Nmap XML into a named network")
    xml_import.add_argument("database", type=Path)
    xml_import.add_argument("xml_file", type=Path)
    xml_import.add_argument("--network", required=True)
    xml_import.add_argument("--operator", default=None)
    xml_import.add_argument("--no-evidence", action="store_true")

    tui = commands.add_parser("tui", help="open the interactive map (plain output when redirected)")
    tui.add_argument("database", type=Path, help="engagement database")

    compare_cmd = commands.add_parser("compare", help="diff two scans of this engagement")
    compare_cmd.add_argument("database", type=Path)
    compare_cmd.add_argument("--from", dest="from_scan", default="", help="older scan id or prefix")
    compare_cmd.add_argument("--to", dest="to_scan", default="", help="newer scan id or prefix")
    compare_cmd.add_argument("--list", action="store_true", dest="list_scans",
                             help="list completed scans")

    demo_cmd = commands.add_parser(
        "demo", help="write a generated demo engagement (no real data)"
    )
    demo_cmd.add_argument("output", type=Path)
    demo_cmd.add_argument("--force", action="store_true", help="replace an existing file")

    export_cmd = commands.add_parser(
        "export", help="write a pseudonymised copy of an engagement"
    )
    export_cmd.add_argument("database", type=Path)
    export_cmd.add_argument("output", type=Path)
    export_cmd.add_argument("--force", action="store_true", help="replace an existing export")

    queue_cmd = commands.add_parser("queue", help="queue scans and run them in order")
    queue_cmd.add_argument("database", type=Path)
    queue_cmd.add_argument("targets", nargs="*", help="targets for --add")
    queue_cmd.add_argument("--network", default="", help="network for --add")
    queue_cmd.add_argument("--nmap-options", dest="queue_options", default="")
    queue_cmd.add_argument("--engine", default="nmap")
    queue_cmd.add_argument("--add", action="store_true", dest="add_job")
    queue_cmd.add_argument("--list", action="store_true", dest="list_queue")
    queue_cmd.add_argument("--remove", default="")
    queue_cmd.add_argument("--clear", action="store_true", dest="clear_queue")
    queue_cmd.add_argument("--run", action="store_true", dest="run_queue")
    queue_cmd.add_argument("--yes", action="store_true")
    queue_cmd.add_argument("--operator", default=None)

    review_cmd = commands.add_parser("review", help="list review items and record decisions")
    review_cmd.add_argument("database", type=Path)
    review_cmd.add_argument("--list", action="store_true", dest="list_review")
    review_cmd.add_argument("--state", default="", help="filter by current state")
    review_cmd.add_argument("--limit", type=int, default=20)
    review_cmd.add_argument("--decide", default="", help="review item id")
    review_cmd.add_argument("--set", dest="set_state", default="",
                            choices=("", *review.DECIDED_STATES))
    review_cmd.add_argument("--note", default="", help="detail recorded with a decision")
    review_cmd.add_argument("--operator", default=None)

    tag_cmd = commands.add_parser("tag", help="attach, list or remove tags")
    tag_cmd.add_argument("database", type=Path)
    tag_cmd.add_argument("names", nargs="*", help="tag names")
    tag_cmd.add_argument("--node", default="", help="topology node id")
    tag_cmd.add_argument("--edge", default="", help="topology edge id")
    tag_cmd.add_argument("--list", action="store_true", dest="list_tags")
    tag_cmd.add_argument("--remove", action="store_true", dest="remove_tags")
    tag_cmd.add_argument("--operator", default=None)

    note = commands.add_parser("note", help="attach or list notes")
    note.add_argument("database", type=Path)
    note.add_argument("body", nargs="?", default="", help="note text (omit with --list)")
    note.add_argument("--node", default="", help="topology node id")
    note.add_argument("--edge", default="", help="topology edge id")
    note.add_argument("--list", action="store_true", dest="list_notes")
    note.add_argument("--operator", default=None)

    report = commands.add_parser("report", help="generate engagement reports")
    report_commands = report.add_subparsers(dest="report_format", required=True)
    markdown = report_commands.add_parser("markdown", help="write a Markdown report")
    markdown.add_argument("database", type=Path)
    markdown.add_argument("output", type=Path)
    svg = report_commands.add_parser(
        "svg", help="write an SVG topology map (dotted links are inferred)"
    )
    svg.add_argument("database", type=Path)
    svg.add_argument("output", type=Path)
    svg.add_argument("--width", type=int, default=1200)
    svg.add_argument("--height", type=int, default=800)
    json_report = report_commands.add_parser("json", help="write the engagement as JSON")
    json_report.add_argument("database", type=Path)
    json_report.add_argument("output", type=Path)
    csv_report = report_commands.add_parser("csv", help="write one row per port as CSV")
    csv_report.add_argument("database", type=Path)
    csv_report.add_argument("output", type=Path)
    html_report = report_commands.add_parser("html", help="write a self-contained HTML page")
    html_report.add_argument("database", type=Path)
    html_report.add_argument("output", type=Path)
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
    outcome = actions.scope_entries(path)
    if not outcome.ok:
        raise DatabaseError(outcome.message)
    entries = outcome.payload
    for entry in entries:
        print(
            f"{'IN' if entry['included'] else 'EXCLUDE'} [engagement-wide] "
            f"{entry['kind']} {entry['value']} "
            f"(author={entry['author'] or '-'}, created={entry['created_at']})"
        )
    if not entries:
        print("No scope rules recorded.")
    return 0


def _open_default(path: Path | None) -> int:
    """Bare `lumos` opens the interface; a path argument opens that database."""
    requested = path or os.environ.get("LUMOS_DB") or None
    if requested is None:
        from .tui.start import run_start_screen

        return run_start_screen()
    database = Path(requested).expanduser()
    if not database.is_file():
        print(f"lumos: no engagement database at {database}", file=sys.stderr)
        return 2
    from .tui.app import run_tui

    local_state.remember_engagement(database)
    return run_tui(database)


SUBCOMMANDS = frozenset(
    {"db", "scope", "interfaces", "scan", "import", "tui", "report", "note", "compare", "tag", "review", "queue", "export", "demo"}
)


def _run_engine_scan(args: argparse.Namespace) -> int:
    """Run a non-Nmap enumerator over every requested target, one scan row each."""
    total_hosts = 0
    for target in args.targets:
        try:
            scan_id, hosts, _message = engine_scan.scan_with_engine(
                args.database,
                args.network,
                args.engine,
                target,
                engine_scan.EngineOptions(
                    ports=args.engine_ports,
                    rate=args.engine_rate,
                    operator=args.operator,
                ),
            )
        except engine_scan.EngineScanError as exc:
            print(f"{args.engine}: {exc}", file=sys.stderr)
            return 1
        total_hosts += hosts
        print(f"Scan {scan_id}: completed; {hosts} host(s) via {args.engine}")
    print(f"{args.engine}: {total_hosts} host(s) total")
    return 0


def _print_progress(text: str) -> None:
    """Print one Nmap progress chunk on its own line.

    Nmap's ``<taskprogress>`` notes arrive without a trailing newline, so
    printing them with ``end=""`` ran the final status line into the last
    progress line.
    """
    line = text.rstrip()
    if line:
        print(line, file=sys.stderr, flush=True)


def _run_scan(args: Any) -> int:
    """Run an Nmap or engine scan and print one summary line."""
    print(AUTHORIZED_USE_NOTICE, file=sys.stderr)
    if args.engine != "nmap":
        return _run_engine_scan(args)
    targets = _merged_targets(args)
    if not targets:
        print("lumos: give at least one target or --target-file", file=sys.stderr)
        return 2
    outcome = scan_database(
        args.database,
        args.network,
        targets,
        nmap_options=args.nmap_options,
        interface=args.interface,
        operator=args.operator,
        executable=args.nmap_executable,
        evidence=not args.no_evidence,
        scope_confirmation=args.confirm_scope,
        on_command=lambda command: _show_command(command, label="Nmap command", yes=args.yes),
        on_progress=_print_progress,
    )
    result = outcome.result
    if result.cancelled:
        status = "cancelled"
    elif result.exit_code == 0 and not result.parse_error:
        status = "completed"
    else:
        status = "failed"
    print(
        f"Scan {outcome.scan_id}: {status}; {result.hosts_seen} host(s); exit {result.exit_code}"
    )
    if result.parse_error:
        print(f"XML parser: {result.parse_error}", file=sys.stderr)
    if result.stderr:
        print(result.stderr, file=sys.stderr)
    return 0 if status == "completed" else 1


def _run_demo(args: Any) -> int:
    """Write the synthetic engagement used by docs and screenshots."""
    try:
        stats = demo.build_demo(args.output, overwrite=args.force)
    except demo.DemoError as exc:
        print(f"lumos: {exc}", file=sys.stderr)
        return 2
    print(
        f"wrote {stats.path}: {stats.hosts} host(s), {stats.scans} scan(s),"
        f" {stats.zones} zone(s), {stats.nodes} node(s), {stats.edges} link(s)"
        " (generated data)"
    )
    return 0


def _run_export(args: Any) -> int:
    """Write a sanitised copy and say what was rewritten."""
    try:
        stats = sanitize.export_sanitised(args.database, args.output, overwrite=args.force)
    except sanitize.SanitizeError as exc:
        print(f"lumos: {exc}", file=sys.stderr)
        return 2
    print(
        f"wrote {args.output}: {stats.addresses} address(es),"
        f" {stats.hostnames} hostname(s), {stats.macs} MAC(s), {stats.networks} network(s)"
        f" rewritten in {stats.rewritten_values} field(s)"
        + (f" and {stats.evidence_rewritten} evidence value(s)" if stats.evidence_rewritten else "")
    )
    return 0


def _run_queue_command(args: Any) -> int:
    """Add, list, remove, clear or run queued scans."""
    try:
        if args.add_job:
            if not args.network:
                print("lumos: --add needs --network", file=sys.stderr)
                return 2
            job = queue.add_job(
                args.database, network=args.network, targets=args.targets,
                nmap_options=args.queue_options, engine=args.engine,
            )
            print(f"queued {job.id[:8]}: {job.summary}")
            return 0
        if args.remove:
            if not queue.remove_job(args.database, args.remove):
                print("lumos: no queued job matches that id", file=sys.stderr)
                return 2
            print(f"removed {args.remove}")
            return 0
        if args.clear_queue:
            print(f"cleared {queue.clear(args.database)} job(s)")
            return 0
        if args.run_queue:
            return _run_queued_scans(args)
        jobs = queue.load_jobs(args.database)
        if not jobs:
            print("the queue is empty")
        for position, job in enumerate(jobs, start=1):
            print(f"{position}. {job.id[:8]}  {job.summary}")
        return 0
    except queue.QueueError as exc:
        print(f"lumos: {exc}", file=sys.stderr)
        return 2


def _run_queued_scans(args: Any) -> int:
    """Run each job in order, stopping at the first failure.

    A failure stops the queue rather than skipping ahead: the next job may have
    been queued *because* of what the failed one would have found.
    """
    try:
        jobs = queue.load_jobs(args.database)
    except queue.QueueError as exc:
        print(f"lumos: {exc}", file=sys.stderr)
        return 2
    if not jobs:
        print("the queue is empty")
        return 0
    print(AUTHORIZED_USE_NOTICE, file=sys.stderr)
    for position, job in enumerate(jobs, start=1):
        print(f"[{position}/{len(jobs)}] {job.summary}", file=sys.stderr)
        if job.engine != "nmap":
            if not _run_engine_job(args, job):
                return 1
            queue.remove_job(args.database, job.id)
            continue
        try:
            outcome = scan_database(
                args.database, job.network, job.targets,
                nmap_options=job.nmap_options,
                operator=args.operator,
                on_command=lambda command: _show_command(
                    command, label="Nmap command", yes=args.yes
                ),
                on_progress=_print_progress,
            )
        except Exception as exc:  # scope refusal, missing nmap, bad option text
            print(f"lumos: queued job stopped the run: {exc}", file=sys.stderr)
            return 2
        result = outcome.result
        if result.cancelled or result.exit_code != 0 or result.parse_error:
            print(
                f"lumos: scan {outcome.scan_id} did not complete;"
                " the rest of the queue is kept",
                file=sys.stderr,
            )
            return 1
        queue.remove_job(args.database, job.id)
        print(f"Scan {outcome.scan_id}: completed; {result.hosts_seen} host(s)")
    print(f"{len(jobs)} job(s) run; the queue is empty")
    return 0


def _run_engine_job(args: Any, job: Any) -> bool:
    """Run one queued non-Nmap job; True when it completed."""
    total = 0
    for target in job.targets:
        try:
            _scan_id, hosts, _message = engine_scan.scan_with_engine(
                args.database, job.network, job.engine, target,
                engine_scan.EngineOptions(
                    ports=job.nmap_options, rate=1000, operator=args.operator
                ),
            )
        except Exception as exc:
            print(f"lumos: queued job stopped the run: {exc}", file=sys.stderr)
            return False
        total += hosts
    print(f"{job.engine}: {total} host(s)")
    return True


def _run_review(args: Any) -> int:
    """List the review queue, or record one decision."""
    try:
        if args.decide:
            if not args.set_state:
                print("lumos: --decide needs --set", file=sys.stderr)
                return 2
            item = review.set_state(
                args.database, args.decide, args.set_state,
                author=args.operator or "operator", detail=args.note,
            )
            print(f"{item.reason_code} -> {item.state}")
            return 0
        items = review.list_items(args.database, limit=args.limit, state=args.state)
        counts = review.states_of(args.database)
        if not items:
            print("nothing to review")
        for item in items:
            print(item.summary)
        total = sum(counts.values())
        print(
            f"{total} item(s): "
            + ", ".join(f"{name} {count}" for name, count in counts.items())
        )
        return 0
    except review.ReviewError as exc:
        print(f"lumos: {exc}", file=sys.stderr)
        return 2


def _merged_targets(args: Any) -> tuple[str, ...]:
    """Typed targets plus the lines of --target-file, deduplicated in order.

    Nmap's own ``-iL`` is refused by the runner; Lumos reads the file so every
    entry passes through the same scope guard as a typed target.
    """
    targets = list(args.targets)
    if getattr(args, "target_file", None):
        for target in read_target_file(args.target_file):
            if target not in targets:
                targets.append(target)
    return tuple(targets)


def _run_report_export(args: Any) -> int:
    """JSON/CSV/HTML share one path: build the file, report the outcome."""
    outcome = actions.write_report(args.database, args.output, report_format=args.report_format)
    print(outcome.message, file=sys.stdout if outcome.ok else sys.stderr)
    return 0 if outcome.ok else 2


def _run_tag(args: Any) -> int:
    target_kind = "engagement"
    target_id = ""
    if args.node:
        target_kind, target_id = "topology_node", args.node
    elif args.edge:
        target_kind, target_id = "topology_edge", args.edge
    try:
        if args.list_tags:
            found = (
                tags.tags_for(args.database, target_kind, target_id) if target_id
                else tags.all_tags(args.database)
            )
            if not found:
                print("no tags")
                return 0
            for tag in found:
                print(f"{tag.name}" + (f"  ({tag.count})" if tag.count else ""))
            return 0
        if not args.names:
            print("lumos: give at least one tag name", file=sys.stderr)
            return 2
        for name in args.names:
            if args.remove_tags:
                gone = tags.remove_tag(
                    args.database, name=name, object_kind=target_kind, object_id=target_id
                )
                print(f"{'removed' if gone else 'not attached'}: {name}")
            else:
                tag = tags.add_tag(
                    args.database, name=name, object_kind=target_kind,
                    object_id=target_id, author=args.operator or "operator",
                )
                print(f"tagged {target_id or 'engagement'}: {tag.name}")
        return 0
    except tags.TagError as exc:
        print(f"lumos: {exc}", file=sys.stderr)
        return 2


def _run_compare(args: Any) -> int:
    try:
        if args.list_scans:
            scans = compare.recent_scans(args.database, limit=20)
            if not scans:
                print("no completed scans")
                return 0
            for scan in scans:
                print(f"{scan.id}  {scan.started_at}  {scan.targets}")
            return 0
        recent = compare.recent_scans(args.database, limit=2)
        if not args.from_scan and not args.to_scan and len(recent) < 2:
            print("lumos: need two completed scans, or use --from/--to", file=sys.stderr)
            return 2
        right = compare.resolve_scan(args.database, args.to_scan) if args.to_scan else recent[0]
        left = compare.resolve_scan(args.database, args.from_scan) if args.from_scan else recent[1]
        print(compare.render_text(compare.diff_scans(args.database, left.id, right.id)), end="")
        return 0
    except compare.CompareError as exc:
        print(f"lumos: {exc}", file=sys.stderr)
        return 2


def _run_note(args: Any) -> int:
    target_kind = "engagement"
    target_id = ""
    if args.node:
        target_kind, target_id = "topology_node", args.node
    elif args.edge:
        target_kind, target_id = "topology_edge", args.edge
    try:
        if args.list_notes:
            found = notes.notes_for(args.database, target_kind=target_kind if target_id else "",
                                    target_id=target_id)
            if not found:
                print("no notes")
                return 0
            for note in found:
                where = note.target_id or "engagement"
                print(f"{note.updated_at}  {where:24}  {note.author}: {note.summary}")
            return 0
        if not args.body:
            print("lumos: a note needs text (or use --list)", file=sys.stderr)
            return 2
        note = notes.add_note(
            args.database, target_kind=target_kind, target_id=target_id,
            body=args.body, author=args.operator or "operator",
        )
        print(f"note {note.id} on {note.target_id or 'engagement'}")
        return 0
    except notes.NoteError as exc:
        print(f"lumos: {exc}", file=sys.stderr)
        return 2


def main(argv: Sequence[str] | None = None) -> int:
    tokens = list(sys.argv[1:] if argv is None else argv)
    if tokens and not tokens[0].startswith("-") and tokens[0] not in SUBCOMMANDS:
        # `lumos PATH` opens the interface on that database.
        if len(tokens) > 1:
            print(f"lumos: unexpected arguments after {tokens[0]}: {' '.join(tokens[1:])}", file=sys.stderr)
            return 2
        return _open_default(Path(tokens[0]))
    parser = _parser()
    args = parser.parse_args(tokens)
    if args.command is None:
        return _open_default(None)
    try:
        simple = {
            "compare": _run_compare, "note": _run_note, "tag": _run_tag,
            "review": _run_review, "queue": _run_queue_command,
            "export": _run_export, "demo": _run_demo,
        }
        if args.command in simple:
            return simple[args.command](args)
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
            result = actions.create_engagement(args.path, args.name)
            if not result.ok:
                raise DatabaseError(result.message)
            print(AUTHORIZED_USE_NOTICE, file=sys.stderr)
            print(f"Created {args.path}")
            return 0
        if args.command == "db" and args.db_command == "upgrade":
            outcome = actions.upgrade(args.path)
            if not outcome.ok:
                raise DatabaseError(outcome.message)
            result = outcome.payload
            print(
                f"Upgraded {args.path} from schema {result['previous_user_version']} "
                f"to {result['user_version']}; engagement uid {result['engagement_uid']}"
            )
            return 0
        if args.command == "db" and args.db_command == "merge":
            outcome = actions.merge(
                args.target, args.source, operator=args.operator, dry_run=args.dry_run
            )
            if not outcome.ok:
                raise DatabaseError(outcome.message)
            stats = outcome.payload
            copied = ", ".join(f"{table} {count}" for table, count in stats.rows.items() if count) or "nothing new"
            verb = "Would copy" if stats.dry_run else "Merged"
            print(f"{verb}: {copied}; total {stats.total} rows")
            return 0
        if args.command == "db" and args.db_command == "rebuild":
            outcome = actions.rebuild(args.path)
            if not outcome.ok:
                raise DatabaseError(outcome.message)
            stats = outcome.payload
            if args.json:
                print(json.dumps(asdict(stats), sort_keys=True))
            else:
                print(
                    f"Rebuilt {stats.hubs} hubs, {stats.edges} links "
                    f"({stats.local_edges} local), {stats.memberships} memberships; "
                    f"removed {stats.removed_edges} stale links and {stats.removed_hubs} stale hubs."
                )
            return 0
        if args.command == "db" and args.db_command == "check":
            outcome = actions.check(args.path)
            if not outcome.ok:
                raise DatabaseError(outcome.message)
            result = outcome.payload
            print(
                f"Valid Lumos database: schema {result['user_version']}; "
                f"{result['tables']} tables; {result['views']} views; "
                f"integrity {result['integrity']}; engagement uid {result['engagement_uid']}"
            )
            return 0
        if args.command == "scope" and args.scope_command == "add":
            outcome = actions.add_scope(
                args.database,
                args.target,
                network=args.network,
                included=not args.exclude,
                author=args.author,
            )
            if not outcome.ok:
                raise ValueError(outcome.message)
            network_id, inserted = outcome.payload.get("network_id", ""), outcome.payload["inserted"]
            print(f"{'Added' if inserted else 'Already present'} {'include' if not args.exclude else 'exclude'} rule in network {args.network!r} ({network_id})")
            return 0
        if args.command == "scope" and args.scope_command == "show":
            return _scope_show(args.database)
        if args.command == "scan":
            return _run_scan(args)
        if args.command == "import":
            outcome = actions.import_xml(
                args.database,
                args.xml_file,
                network=args.network,
                operator=args.operator,
                evidence=not args.no_evidence,
            )
            scan_id = (outcome.payload or {}).get("scan_id", "")
            hosts = (outcome.payload or {}).get("hosts", 0)
            status = "completed" if outcome.ok else "partial/failed"
            print(f"XML import {scan_id}: {status}; {hosts} host(s)")
            if not outcome.ok:
                print(outcome.detail or outcome.message, file=sys.stderr)
                return 1
            return 0
        if args.command == "tui":
            from .tui.app import run_tui

            return run_tui(args.database)
        if args.command == "report" and args.report_format == "svg":
            outcome = actions.write_report(
                args.database, args.output, report_format="svg", width=args.width, height=args.height
            )
            if not outcome.ok:
                raise OSError(outcome.message)
            print(f"Wrote {args.output}")
            return 0
        if args.command == "report" and args.report_format in {"json", "csv", "html"}:
            return _run_report_export(args)
        if args.command == "report" and args.report_format == "markdown":
            outcome = actions.write_report(args.database, args.output, report_format="markdown")
            if not outcome.ok:
                raise OSError(outcome.message)
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
