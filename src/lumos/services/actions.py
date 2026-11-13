"""Curses-free operations shared by the CLI and the terminal interface.

Every function here returns an :class:`ActionResult` instead of printing or
raising for expected failures, so a front end can decide how to show the same
outcome. Nothing in this module imports curses, reads the terminal, or blocks
on user input.
"""

from __future__ import annotations

import getpass
import queue
import shlex
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Sequence

from ..core import state
from ..core.database import (
    DatabaseError,
    check_database,
    initialize_database,
    open_database,
    upgrade_database,
)
from ..core.inference import rebuild_inferred
from ..core.merge import MergeError, merge_engagement
from ..core.nmap.iflist import discover_interfaces
from ..core.nmap.runner import NmapRunnerError
from ..core.reports import (
    write_csv_report,
    write_html_report,
    write_json_report,
    write_markdown_report,
    write_svg_report,
)
from ..core.scan_store import ScanStoreError, reconcile_interrupted_scans
from ..core.scanning import ScopeConfirmationRequired, scan_database
from ..core.scope import is_target_in_scope, parse_target
from ..core.scope_store import add_scope_rule, ensure_network, get_network, read_scope_rules
from ..core.text import sanitize_text
from ..core.vantage_store import save_interfaces as persist_interfaces
from ..core.xml_import import import_nmap_xml

# The Phase 2 runner only accepts -sS, -sT, -sU and -sV, so there is no
# ping-only preset; a connect scan over the top ports is the safe default.
SCAN_PRESETS: dict[str, str] = {
    "connect": "-sT",
    "service": "-sV --top-ports 100",
    "udp": "-sU --top-ports 50",
    "custom": "",
}


@dataclass(frozen=True)
class ActionResult:
    ok: bool
    message: str
    detail: str = ""
    payload: Any = None


def _ok(message: str, *, detail: str = "", payload: Any = None) -> ActionResult:
    return ActionResult(True, message, detail, payload)


def _fail(message: str, *, detail: str = "", payload: Any = None) -> ActionResult:
    return ActionResult(False, message, detail, payload)


def _guarded(operation: Callable[[], ActionResult]) -> ActionResult:
    """Run one operation and turn expected failures into a message."""
    try:
        return operation()
    except ScopeConfirmationRequired as exc:
        return _fail(
            "blocked: out of scope",
            detail=f"Type the exact phrase to override: {exc.confirmation_text}",
        )
    except (DatabaseError, MergeError, NmapRunnerError, ScanStoreError, sqlite3.Error, OSError, ValueError) as exc:
        return _fail(str(exc))


# --------------------------------------------------------------------------
# Engagements


def create_engagement(
    path: str | Path, name: str, *, client: str = "", operator: str = ""
) -> ActionResult:
    """Create an owner-only database; never overwrite an existing file."""

    def run() -> ActionResult:
        target = Path(path).expanduser().absolute()
        if target.exists():
            return _fail(f"{target} already exists; choose another path or open it")
        cleaned = sanitize_text(name, max_chars=256).strip()
        if not cleaned:
            return _fail("an engagement name is required")
        initialize_database(target, cleaned)
        if client or operator:
            conn = open_database(target, readonly=False)
            try:
                with conn:
                    conn.execute(
                        "UPDATE engagement SET client = ?, operator = ?",
                        (sanitize_text(client, max_chars=256), sanitize_text(operator, max_chars=256)),
                    )
            finally:
                conn.close()
        state.remember_engagement(target, cleaned)
        return _ok(f"created {target.name}", detail=str(target), payload={"path": str(target), "name": cleaned})

    return _guarded(run)


def open_engagement(path: str | Path) -> ActionResult:
    """Validate and remember an existing database."""

    def run() -> ActionResult:
        target = Path(path).expanduser().absolute()
        if not target.is_file():
            return _fail(f"no database at {target}")
        result = check_database(target)
        interrupted = reconcile_interrupted_scans(target)
        name = _engagement_name(target)
        state.remember_engagement(target, name)
        return _ok(
            f"opened {name or target.name}",
            detail=f"schema {result['user_version']}"
            + (f"; {interrupted} interrupted scan(s) closed" if interrupted else ""),
            payload={"path": str(target), "name": name},
        )

    return _guarded(run)


def _engagement_name(path: Path) -> str:
    conn = open_database(path, readonly=True)
    try:
        row = conn.execute("SELECT name FROM engagement LIMIT 1").fetchone()
        return str(row[0]) if row else ""
    finally:
        conn.close()


def recent_engagements() -> list[dict]:
    return state.recent_engagements()


# --------------------------------------------------------------------------
# Scope


def scope_entries(database: str | Path) -> ActionResult:
    def run() -> ActionResult:
        conn = open_database(database, readonly=True)
        try:
            rows = conn.execute(
                "SELECT id, included, rule_kind, rule_value, author, created_at "
                "FROM scope_rules ORDER BY included DESC, rule_kind, rule_value"
            ).fetchall()
        finally:
            conn.close()
        entries = [
            {
                "id": str(row[0]),
                "included": bool(row[1]),
                "kind": str(row[2]),
                "value": str(row[3]),
                "author": str(row[4] or ""),
                "created_at": str(row[5]),
            }
            for row in rows
        ]
        includes = sum(1 for entry in entries if entry["included"])
        return _ok(
            f"{includes} include, {len(entries) - includes} exclude",
            payload=entries,
        )

    return _guarded(run)


def add_scope(
    database: str | Path,
    target: str,
    *,
    network: str = "default",
    included: bool = True,
    author: str = "",
) -> ActionResult:
    def run() -> ActionResult:
        value = sanitize_text(target, max_chars=256).strip()
        if not value:
            return _fail("a target is required")
        parse_target(value)  # strict syntax check before touching the database
        _, inserted = add_scope_rule(
            database, network or "default", value, included=included, author=author
        )
        verb = "include" if included else "exclude"
        return _ok(
            f"{'added' if inserted else 'already present'}: {verb} {value}",
            payload={"inserted": inserted},
        )

    return _guarded(run)


def remove_scope(database: str | Path, rule_id: str) -> ActionResult:
    def run() -> ActionResult:
        conn = open_database(database, readonly=False)
        try:
            with conn:
                cursor = conn.execute("DELETE FROM scope_rules WHERE id = ?", (rule_id,))
            removed = cursor.rowcount
        finally:
            conn.close()
        if not removed:
            return _fail("that rule no longer exists")
        return _ok("scope rule removed")

    return _guarded(run)


def scope_values(database: str | Path) -> tuple[str, ...]:
    result = scope_entries(database)
    entries = result.payload if result.ok else []
    return tuple(entry["value"] for entry in entries if entry["included"])


# --------------------------------------------------------------------------
# Scans


def preview_scan(
    database: str | Path,
    targets: Sequence[str],
    *,
    network: str,
    preset: str = "discover",
    extra_options: str = "",
) -> ActionResult:
    """Check scope before a scan is offered for confirmation."""

    def run() -> ActionResult:
        cleaned = [sanitize_text(target, max_chars=256).strip() for target in targets if str(target).strip()]
        if not cleaned:
            return _fail("at least one target is required")
        for target in cleaned:
            parse_target(target)
        ensure_network(database, network or "default")
        engagement_id, _ = get_network(database, network or "default")
        rules = read_scope_rules(database, engagement_id)
        outside = [target for target in cleaned if not is_target_in_scope(target, rules).allowed]
        phrase = "SCAN OUT OF SCOPE: " + ", ".join(sorted(set(outside))) if outside else ""
        options = f"{SCAN_PRESETS.get(preset, '')} {extra_options}".strip()
        return _ok(
            "in scope" if not outside else f"{len(outside)} target(s) outside scope",
            payload={
                "targets": cleaned,
                "network": network,
                "options": options,
                "outside": outside,
                "phrase": phrase,
            },
        )

    return _guarded(run)


class ScanJob:
    """One scan running on a worker thread, reporting through a queue."""

    def __init__(
        self,
        database: str | Path,
        targets: Sequence[str],
        *,
        network: str,
        options: str = "",
        interface: str = "",
        operator: str | None = None,
        evidence: bool = True,
        scope_confirmation: str = "",
        executable: str | None = None,
    ) -> None:
        self.database = Path(database)
        self.started_at = time.monotonic()
        self.events: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.cancel_event = threading.Event()
        self._done = threading.Event()
        self._thread = threading.Thread(target=self._run, name="lumos-scan", daemon=True)
        self._arguments = {
            "targets": list(targets),
            "network": network,
            "options": options,
            "interface": interface,
            "operator": operator,
            "evidence": evidence,
            "scope_confirmation": scope_confirmation,
            "executable": executable,
        }

    def start(self) -> "ScanJob":
        self._thread.start()
        return self

    @property
    def finished(self) -> bool:
        return self._done.is_set()

    @property
    def elapsed(self) -> float:
        return time.monotonic() - self.started_at

    def cancel(self) -> None:
        self.cancel_event.set()

    def drain(self) -> list[tuple[str, Any]]:
        items = []
        while True:
            try:
                items.append(self.events.get_nowait())
            except queue.Empty:
                return items

    def _run(self) -> None:
        arguments = self._arguments
        try:
            outcome = scan_database(
                self.database,
                arguments["network"],
                arguments["targets"],
                nmap_options=arguments["options"],
                interface=arguments["interface"],
                operator=arguments["operator"],
                executable=arguments["executable"],
                evidence=arguments["evidence"],
                scope_confirmation=arguments["scope_confirmation"],
                on_command=lambda argv: self.events.put(("command", shlex.join(list(argv)))),
                on_progress=lambda text: self.events.put(("progress", text)),
                cancel_event=self.cancel_event,
            )
        except ScopeConfirmationRequired as exc:
            self.events.put(("done", _fail(f"blocked: {exc.confirmation_text}", detail="out of scope")))
        except (DatabaseError, NmapRunnerError, ScanStoreError, sqlite3.Error, OSError, ValueError) as exc:
            self.events.put(("done", _fail(str(exc))))
        except BaseException as exc:  # a worker thread must never die silently
            self.events.put(("done", _fail(f"scan failed: {exc}")))
        else:
            status = (
                "cancelled"
                if outcome.result.cancelled
                else "completed"
                if outcome.result.exit_code == 0 and not outcome.result.parse_error
                else "failed"
            )
            message = (
                f"scan {status}: {outcome.result.hosts_seen} host(s)"
                + (f"; exit {outcome.result.exit_code}" if status != "completed" else "")
            )
            self.events.put(
                (
                    "done",
                    ActionResult(
                        status == "completed",
                        message,
                        detail=outcome.result.parse_error or outcome.result.stderr,
                        payload={"scan_id": outcome.scan_id, "status": status, "hosts": outcome.result.hosts_seen},
                    ),
                )
            )
        finally:
            self._done.set()


# --------------------------------------------------------------------------
# Import, reports, maintenance


def import_xml(
    database: str | Path,
    xml_file: str | Path,
    *,
    network: str = "default",
    operator: str | None = None,
    evidence: bool = True,
) -> ActionResult:
    def run() -> ActionResult:
        source = Path(xml_file).expanduser().absolute()
        if not source.is_file():
            return _fail(f"no XML file at {source}")
        ensure_network(database, network or "default")
        scan_id, hosts, parse_error = import_nmap_xml(
            database, network, source, operator=operator, evidence=evidence
        )
        if parse_error:
            return _fail(f"imported {hosts} host(s) with errors", detail=parse_error, payload={"scan_id": scan_id})
        return _ok(f"imported {hosts} host(s) from {source.name}", payload={"scan_id": scan_id, "hosts": hosts})

    return _guarded(run)


def default_report_path(database: str | Path, report_format: str) -> Path:
    path = Path(database).expanduser().absolute()
    stamp = time.strftime("%Y%m%d-%H%M%S")
    suffix = {
        "svg": "svg", "json": "json", "csv": "csv", "html": "html",
    }.get(report_format, "md")
    return path.parent / "reports" / f"{path.stem}-{stamp}.{suffix}"


def write_report(
    database: str | Path,
    output: str | Path,
    *,
    report_format: str = "markdown",
    width: int = 1200,
    height: int = 800,
    overwrite: bool = False,
) -> ActionResult:
    def run() -> ActionResult:
        target = Path(output).expanduser().absolute()
        if target.exists() and not overwrite:
            return _fail(f"{target} exists; choose another name or confirm overwrite")
        target.parent.mkdir(parents=True, exist_ok=True)
        writers = {
            "svg": lambda: write_svg_report(database, target, width=width, height=height),
            "markdown": lambda: write_markdown_report(database, target),
            "json": lambda: write_json_report(database, target),
            "csv": lambda: write_csv_report(database, target),
            "html": lambda: write_html_report(database, target),
        }
        writer = writers.get(report_format)
        if writer is None:
            return _fail(f"unknown report format {report_format!r}")
        writer()
        return _ok(f"wrote {target.name}", detail=str(target), payload={"path": str(target)})

    return _guarded(run)


def check(database: str | Path) -> ActionResult:
    def run() -> ActionResult:
        result = check_database(database)
        return _ok(
            f"schema {result['user_version']}; {result['tables']} tables; "
            f"{result['views']} views; integrity {result['integrity']}",
            payload=result,
        )

    return _guarded(run)


def upgrade(database: str | Path) -> ActionResult:
    def run() -> ActionResult:
        result = upgrade_database(database)
        return _ok(
            f"schema {result['previous_user_version']} -> {result['user_version']}",
            payload=result,
        )

    return _guarded(run)


def rebuild(database: str | Path) -> ActionResult:
    def run() -> ActionResult:
        stats = rebuild_inferred(database)
        return _ok(
            f"{stats.hubs} hubs, {stats.edges} links ({stats.local_edges} local), "
            f"{stats.memberships} memberships; removed {stats.removed_edges} links, "
            f"{stats.removed_hubs} hubs",
            payload=stats,
        )

    return _guarded(run)


def merge(
    target: str | Path,
    source: str | Path,
    *,
    operator: str = "",
    dry_run: bool = False,
) -> ActionResult:
    def run() -> ActionResult:
        source_path = Path(source).expanduser().absolute()
        if not source_path.is_file():
            return _fail(f"no database at {source_path}")
        stats = merge_engagement(target, source_path, operator=operator, dry_run=dry_run)
        changed = {table: count for table, count in stats.rows.items() if count}
        summary = ", ".join(f"{table} {count}" for table, count in sorted(changed.items())) or "nothing new"
        verb = "would copy" if stats.dry_run else "merged"
        return _ok(f"{verb}: {summary}; {stats.total} rows", payload=stats)

    return _guarded(run)


def save_interfaces(database: str | Path) -> ActionResult:
    def run() -> ActionResult:
        snapshot = discover_interfaces()
        vantage_id, saved = persist_interfaces(database, snapshot)
        lines = [
            f"{item.name} {item.address or 'no address'} {item.interface_type} {'up' if item.is_up else 'down'}"
            for item in snapshot.interfaces
        ]
        return _ok(
            f"saved {saved} interface(s) to vantage {vantage_id[:8]}",
            detail="\n".join(lines),
            payload={"saved": saved, "vantage_id": vantage_id},
        )

    return _guarded(run)


def default_operator() -> str:
    return sanitize_text(getpass.getuser(), max_chars=256)


@dataclass
class ActivityLog:
    """Bounded in-memory event log the interface can show and save."""

    limit: int = 200
    entries: list[tuple[str, str, str, str]] = field(default_factory=list)

    def add(self, severity: str, message: str, detail: str = "") -> None:
        self.entries.append((time.strftime("%H:%M:%S"), severity, message, sanitize_text(detail, max_chars=2000)))
        if len(self.entries) > self.limit:
            del self.entries[: len(self.entries) - self.limit]

    def write_to(self, path: str | Path) -> Path:
        target = Path(path).expanduser().absolute()
        target.write_text(
            "\n".join(f"{stamp} {severity:<7} {message} {detail}".rstrip() for stamp, severity, message, detail in self.entries)
            + ("\n" if self.entries else ""),
            encoding="utf-8",
        )
        return target
