"""Writable flows: engagements, scope, scans, imports, reports, tools, log."""

from __future__ import annotations

import curses
import threading
from dataclasses import dataclass
import time
from collections import deque
from pathlib import Path
from typing import Any, Callable

from ..core import engine_scan, engines
from ..services import actions
from . import forms
from . import mouse
from .widgets import (
    clear_overlays,
    clear_region,
    clip,
    draw_box,
    remember_overlay,
    safe_addstr,
)


# Verbose scan output: a bounded tail, scrolled with PgUp/PgDn.
SCAN_LOG_LINES = 200


def _attr(styles: dict[str, int], name: str, default: int = 0) -> int:
    return styles.get(name, default)


def _box(window: Any, styles: dict[str, int], unicode_ok: bool, *, title: str, width: int = 72, height: int = 12):
    total_height, total_width = window.getmaxyx()
    box_width = min(width, max(20, total_width - 2))
    box_height = min(height, max(6, total_height - 2))
    top = max(0, (total_height - box_height) // 2)
    left = max(0, (total_width - box_width) // 2)
    clear_overlays(window)
    remember_overlay(window, (top, left, box_height, box_width))
    clear_region(window, (top - 2, left - 2, box_height + 4, box_width + 4))
    return draw_box(
        window,
        top,
        left,
        box_height,
        box_width,
        title=f" {title} ",
        border_attr=_attr(styles, "border_focus"),
        title_attr=_attr(styles, "brand"),
        unicode_ok=unicode_ok,
    )


def show_result(
    window: Any,
    styles: dict[str, int],
    unicode_ok: bool,
    title: str,
    result: actions.ActionResult,
) -> None:
    """Show an outcome until a key is pressed."""
    itop, ileft, ih, iw = _box(window, styles, unicode_ok, title=title, height=10)
    severity = "accent" if result.ok else "error"
    safe_addstr(window, itop, ileft, clip(result.message, iw), iw, _attr(styles, severity), unicode_ok=unicode_ok)
    row = itop + 2
    for line in (result.detail or "").splitlines():
        if row >= itop + ih - 2:
            break
        safe_addstr(window, row, ileft, clip(line, iw), iw, _attr(styles, "muted"), unicode_ok=unicode_ok)
        row += 1
    safe_addstr(
        window,
        itop + ih - 1,
        ileft,
        "press any key",
        iw,
        _attr(styles, "muted"),
        unicode_ok=unicode_ok,
    )
    mouse.add(itop - 1, ileft - 1, ih + 2, iw + 2, {"kind": "close"})
    window.refresh()
    window.timeout(-1)
    try:
        window.getch()
    finally:
        window.timeout(1000)


def run_task(
    window: Any,
    styles: dict[str, int],
    unicode_ok: bool,
    label: str,
    task: Callable[[], actions.ActionResult],
) -> actions.ActionResult:
    """Run one action off the UI thread, drawing a progress panel meanwhile."""
    import threading

    outcome: dict[str, actions.ActionResult] = {}

    def target() -> None:
        try:
            outcome["value"] = task()
        except BaseException as exc:  # a worker must never take the UI down
            outcome["value"] = actions.ActionResult(False, f"{label} failed: {exc}")

    worker = threading.Thread(target=target, name="lumos-task", daemon=True)
    started = time.monotonic()
    worker.start()
    window.timeout(120)
    try:
        frame = 0
        while worker.is_alive():
            itop, ileft, ih, iw = _box(window, styles, unicode_ok, title=label, height=8)
            dots = "." * (1 + frame % 3)
            safe_addstr(
                window,
                itop,
                ileft,
                f"{label}{dots}  {time.monotonic() - started:.1f}s",
                iw,
                _attr(styles, "accent"),
                unicode_ok=unicode_ok,
            )
            safe_addstr(
                window,
                itop + ih - 1,
                ileft,
                "please wait; the interface stays responsive",
                iw,
                _attr(styles, "muted"),
                unicode_ok=unicode_ok,
            )
            window.refresh()
            window.getch()
            frame += 1
    finally:
        window.timeout(1000)
    worker.join()
    return outcome.get("value") or actions.ActionResult(False, f"{label} returned nothing")


# --------------------------------------------------------------------------
# New engagement / open


def flow_new_engagement(window: Any, styles: dict[str, int], unicode_ok: bool) -> Path | None:
    values = forms.run_form(
        window,
        styles,
        unicode_ok,
        "new engagement",
        [
            forms.Field("name", "name", hint="required"),
            forms.Field("client", "client"),
            forms.Field("operator", "operator", value=actions.default_operator()),
            forms.Field("path", "database", value="engagement.sqlite"),
        ],
        note="Creates an owner-only SQLite database; never overwrites.",
    )
    if values is None:
        return None
    result = run_task(
        window,
        styles,
        unicode_ok,
        "creating database",
        lambda: actions.create_engagement(
            values["path"],
            values["name"],
            client=values["client"],
            operator=values["operator"],
        ),
    )
    show_result(window, styles, unicode_ok, "new engagement", result)
    if not result.ok:
        return None
    return Path(result.payload["path"])


def flow_open_path(window: Any, styles: dict[str, int], unicode_ok: bool) -> Path | None:
    values = forms.run_form(
        window,
        styles,
        unicode_ok,
        "open database",
        [forms.Field("path", "path", value=str(Path.cwd() / "engagement.sqlite"))],
    )
    if values is None:
        return None
    result = run_task(
        window,
        styles,
        unicode_ok,
        "opening database",
        lambda: actions.open_engagement(values["path"]),
    )
    show_result(window, styles, unicode_ok, "open database", result)
    return Path(result.payload["path"]) if result.ok else None


# --------------------------------------------------------------------------
# Scope


_SCOPE_STATE = {"index": 0}


def flow_scope(window: Any, styles: dict[str, int], unicode_ok: bool, database: Path) -> actions.ActionResult | None:
    """List, add and remove scope rules."""
    message = ""
    window.timeout(-1)
    try:
        while True:
            listing = actions.scope_entries(database)
            entries = listing.payload or []
            index = _SCOPE_STATE["index"]
            index = max(0, min(index, max(0, len(entries) - 1)))
            height, width = window.getmaxyx()
            box_height = min(max(10, len(entries) + 7), max(8, height - 2))
            itop, ileft, ih, iw = _box(
                window, styles, unicode_ok, title="scope", width=78, height=box_height
            )
            safe_addstr(
                window,
                itop,
                ileft,
                f"{listing.message}   (include rules are what a scan may touch)",
                iw,
                _attr(styles, "muted"),
                unicode_ok=unicode_ok,
            )
            row = itop + 2
            if not entries:
                safe_addstr(window, row, ileft, "no scope rules yet; press a to add one", iw, _attr(styles, "muted"), unicode_ok=unicode_ok)
            for position, entry in enumerate(entries):
                if row >= itop + ih - 3:
                    break
                prefix = "› " if position == index else "  "
                kind = "IN " if entry["included"] else "EX"
                line = f"{prefix}{kind} {entry['kind']:<8} {entry['value']}  ({entry['author'] or '-'})"
                attr = _attr(styles, "accent") if position == index else _attr(styles, "text")
                safe_addstr(window, row, ileft, clip(line, iw), iw, attr, unicode_ok=unicode_ok)
                row += 1
            if message:
                safe_addstr(window, itop + ih - 2, ileft, clip(message, iw), iw, _attr(styles, "accent"), unicode_ok=unicode_ok)
            safe_addstr(
                window,
                itop + ih - 1,
                ileft,
                "a add   d delete   j/k move   Esc back",
                iw,
                _attr(styles, "muted"),
                unicode_ok=unicode_ok,
            )
            mouse.add(itop + ih - 1, ileft, 1, iw, {"kind": "cancel_scan"})
            window.refresh()
            key = window.getch()
            if key == -1:
                continue
            if mouse.is_mouse(key):
                _event, action = mouse.read_action(window)
                if str((action or {}).get("kind", "")) != "cancel_scan":
                    confirm_cancel = False
                    continue
                key = 27
            if key == 27:
                return None
            if key in (forms.curses_keys.UP, ord("k")):
                index -= 1
            elif key in (forms.curses_keys.DOWN, ord("j")):
                index += 1
            elif key == ord("a"):
                added = _add_scope_form(window, styles, unicode_ok, database)
                if added is not None:
                    message = added.message
            elif key == ord("d") and entries:
                entry = entries[index]
                if forms.confirm(window, styles, unicode_ok, f"Delete {entry['value']}?", detail="The rule is removed from the engagement."):
                    message = actions.remove_scope(database, entry["id"]).message
            _SCOPE_STATE["index"] = index
    finally:
        window.timeout(1000)


def _add_scope_form(
    window: Any, styles: dict[str, int], unicode_ok: bool, database: Path
) -> actions.ActionResult | None:
    values = forms.run_form(
        window,
        styles,
        unicode_ok,
        "add scope rule",
        [
            forms.Field("target", "target", hint="IP, CIDR, range or hostname"),
            forms.Field("network", "network", value="default"),
            forms.Field("included", "include", value="1", kind="bool", hint="allow scanning"),
            forms.Field("author", "author", value=actions.default_operator()),
        ],
        note="Include rules define what may be scanned. Excludes win over includes.",
    )
    if values is None:
        return None
    return actions.add_scope(
        database,
        values["target"],
        network=values["network"] or "default",
        included=values["included"] in {"1", "true", "yes", "on"},
        author=values["author"],
    )


# --------------------------------------------------------------------------
# Scan


def _interface_choices() -> tuple[str, ...]:
    try:
        snapshot = actions.discover_interfaces()
    except Exception:
        return ("auto",)
    names = tuple(item.name for item in snapshot.interfaces if item.is_up) or ("auto",)
    return ("auto",) + tuple(name for name in names if name != "auto")


ENGINE_POLL_SECONDS = 0.15


def engine_choices() -> tuple[str, ...]:
    """Engines the operator can actually use: installed and switched on.

    nmap always leads because it is the only one that reports services; the
    port-only tools are useful, but they are not a substitute for -sV.
    """
    enabled = engines.load_enabled()
    found = engines.detect()
    names = [engine.name for engine in engines.ENGINES
             if found.get(engine.name) and engine.name in enabled]
    if "nmap" in names:
        names.remove("nmap")
        names.insert(0, "nmap")
    return tuple(names) or ("nmap",)


@dataclass(frozen=True)
class EngineRequest:
    """What to run: which engine, where, and against which targets."""

    engine: str
    targets: tuple[str, ...]
    network: str
    operator: str


def _engine_scan_flow(
    window: Any,
    styles: dict[str, int],
    unicode_ok: bool,
    database: Path,
    request: EngineRequest,
) -> actions.ActionResult:
    """Run a port-only enumerator. These tools stream nothing, so this waits.

    The worker is a daemon thread because a half-imported scan is still useful
    evidence: closing the panel leaves the run going and the results land in the
    database when it finishes.
    """
    outcome: list[tuple[bool, str]] = []

    def work() -> None:
        try:
            total = 0
            for target in request.targets:
                _scan_id, hosts, _message = engine_scan.scan_with_engine(
                    database, request.network, request.engine, target,
                    engine_scan.EngineOptions(operator=request.operator),
                )
                total += hosts
            outcome.append((
                True,
                f"{request.engine}: {total} host(s) from {len(request.targets)} target(s)",
            ))
        except engine_scan.EngineScanError as exc:
            outcome.append((False, str(exc)))
        except Exception as exc:  # a worker must never die silently
            outcome.append((False, f"{request.engine} failed: {exc}"))

    worker = threading.Thread(target=work, daemon=True)
    worker.start()
    started = time.monotonic()
    window.timeout(int(ENGINE_POLL_SECONDS * 1000))
    try:
        while not outcome:
            itop, ileft, ih, iw = _box(
                window, styles, unicode_ok, title="scanning", width=64, height=7
            )
            elapsed = time.monotonic() - started
            safe_addstr(
                window, itop, ileft,
                clip(f"enumerating with {request.engine}   {elapsed:.1f}s", iw), iw,
                _attr(styles, "accent"), unicode_ok=unicode_ok,
            )
            safe_addstr(
                window, itop + 2, ileft,
                clip(f"{len(request.targets)} target(s); ports only, no service detection", iw), iw,
                _attr(styles, "muted"), unicode_ok=unicode_ok,
            )
            safe_addstr(
                window, itop + ih - 1, ileft,
                "Esc returns to the map; the scan keeps running", iw,
                _attr(styles, "muted"), unicode_ok=unicode_ok,
            )
            window.refresh()
            if window.getch() == 27:
                return actions.ActionResult(
                    True, f"{request.engine} is still running in the background"
                )
    finally:
        window.timeout(1000)
    ok, message = outcome[0]
    return actions.ActionResult(ok, message)


def flow_scan(
    window: Any, styles: dict[str, int], unicode_ok: bool, database: Path
) -> actions.ActionResult | None:
    scope_targets = " ".join(actions.scope_values(database))
    values = forms.run_form(
        window,
        styles,
        unicode_ok,
        "scan",
        [
            forms.Field("targets", "targets", value=scope_targets, hint="space separated"),
            forms.Field("network", "network", value="default"),
            forms.Field(
                "preset", "preset", value="connect", kind="choice",
                choices=("connect", "service", "udp", "custom"),
            ),
            forms.Field("options", "options", hint="extra Nmap options"),
            forms.Field("interface", "interface", value="auto", kind="choice", choices=_interface_choices()),
            forms.Field("evidence", "evidence", value="1", kind="bool", hint="keep raw XML"),
            forms.Field(
                "engine", "engine", value=engine_choices()[0], kind="choice",
                choices=engine_choices(), hint="port-only tools skip -sV",
            ),
        ],
        note=(
            "nmap reports services; port-only engines are faster but skip -sV. "
            "Targets stay scope-checked."
        ),
        validate=lambda field_values: None
        if field_values["targets"].strip()
        else "at least one target is required",
    )
    if values is None:
        return None
    targets = [item for item in values["targets"].replace(",", " ").split() if item]
    network = values["network"] or "default"
    preview = actions.preview_scan(
        database,
        targets,
        network=network,
        preset=values["preset"],
        extra_options=values["options"],
    )
    if not preview.ok:
        show_result(window, styles, unicode_ok, "scan", preview)
        return preview
    phrase = ""
    if preview.payload["outside"]:
        outside = ", ".join(sorted(set(preview.payload["outside"])))
        plural = "are" if len(preview.payload["outside"]) > 1 else "is"
        confirmed = forms.confirm_scope(
            window,
            styles,
            unicode_ok,
            title="out of scope",
            lines=[
                f"{outside} {plural} not covered by an included scope rule.",
                "Scanning anyway is recorded in the audit log with these exact targets.",
            ],
            checkbox_label="I understand and want to scan outside the scope",
        )
        if not confirmed:
            return None
        # The operator confirmed the same targets the phrase names, so the
        # audit row still records the phrase the CLI would have required.
        phrase = preview.payload["phrase"]
    if values.get("engine", "nmap") != "nmap":
        return _engine_scan_flow(
            window, styles, unicode_ok, database,
            EngineRequest(
                engine=values["engine"],
                targets=tuple(targets),
                network=network,
                operator=values.get("operator") or actions.default_operator(),
            ),
        )
    interface = "" if values["interface"] == "auto" else values["interface"]
    job = actions.ScanJob(
        database,
        targets,
        network=network,
        options=preview.payload["options"],
        interface=interface,
        operator=values.get("operator") or actions.default_operator(),
        evidence=values["evidence"] in {"1", "true", "yes", "on"},
        scope_confirmation=phrase,
    ).start()
    return _watch_scan(window, styles, unicode_ok, job)


def _watch_scan(
    window: Any, styles: dict[str, int], unicode_ok: bool, job: actions.ScanJob
) -> actions.ActionResult:
    lines: deque[str] = deque(maxlen=SCAN_LOG_LINES)
    command = ""
    outcome: actions.ActionResult | None = None
    confirm_cancel = False
    scroll = 0
    window.timeout(150)
    try:
        while outcome is None:
            for kind, payload in job.drain():
                if kind == "command":
                    command = str(payload)
                elif kind == "progress":
                    for text in str(payload).strip().splitlines():
                        if text:
                            lines.append(text)
                            scroll = 0
                elif kind == "done":
                    outcome = payload
            itop, ileft, ih, iw = _box(window, styles, unicode_ok, title="scanning", width=78, height=12)
            if job.cancel_event.is_set():
                state = "cancelling…"
            elif confirm_cancel:
                state = "Esc again to cancel, any other key keeps scanning"
            else:
                state = "running"
            safe_addstr(
                window,
                itop,
                ileft,
                clip(f"{state}  {job.elapsed:.1f}s", iw),
                iw,
                _attr(styles, "error") if confirm_cancel else _attr(styles, "accent"),
                unicode_ok=unicode_ok,
            )
            if command:
                safe_addstr(
                    window, itop + 1, ileft, clip(command, iw), iw,
                    _attr(styles, "muted"), unicode_ok=unicode_ok,
                )
            row = itop + 3
            capacity = max(1, ih - 5)
            tail = list(lines)
            if scroll:
                tail = tail[: max(0, len(tail) - scroll)]
            shown = tail[-capacity:] or ["Nmap is working; hosts appear when the XML lands."]
            for line in shown:
                if row >= itop + ih - 1:
                    break
                safe_addstr(window, row, ileft, clip(line, iw), iw, _attr(styles, "text"), unicode_ok=unicode_ok)
                row += 1
            safe_addstr(
                window,
                itop + ih - 1,
                ileft,
                (
                    "Esc twice cancels; finished hosts are kept"
                    if not job.cancel_event.is_set()
                    else "cancelling; finished hosts are kept"
                ),
                iw,
                _attr(styles, "muted"),
                unicode_ok=unicode_ok,
            )
            mouse.add(itop + ih - 1, ileft, 1, iw, {"kind": "cancel_scan"})
            window.refresh()
            key = window.getch()
            if key == -1:
                continue
            if mouse.is_mouse(key):
                _event, action = mouse.read_action(window)
                if str((action or {}).get("kind", "")) != "cancel_scan":
                    confirm_cancel = False
                    continue
                key = 27
            if key == 27:
                if job.cancel_event.is_set():
                    continue
                if confirm_cancel:
                    job.cancel()
                else:
                    confirm_cancel = True
            else:
                confirm_cancel = False
    finally:
        window.timeout(1000)
    return outcome or actions.ActionResult(False, "scan ended without a result")


# --------------------------------------------------------------------------
# Import, report, tools, log


def flow_import(window: Any, styles: dict[str, int], unicode_ok: bool, database: Path) -> actions.ActionResult | None:
    values = forms.run_form(
        window,
        styles,
        unicode_ok,
        "import Nmap XML",
        [
            forms.Field("xml", "xml file", value=str(Path.cwd() / "scan.xml")),
            forms.Field("network", "network", value="default"),
            forms.Field("evidence", "evidence", value="1", kind="bool", hint="keep raw XML"),
            forms.Field(
                "engine", "engine", value=engine_choices()[0], kind="choice",
                choices=engine_choices(), hint="port-only tools skip -sV",
            ),
        ],
    )
    if values is None:
        return None
    result = run_task(
        window,
        styles,
        unicode_ok,
        "importing",
        lambda: actions.import_xml(
            database,
            values["xml"],
            network=values["network"] or "default",
            evidence=values["evidence"] in {"1", "true", "yes", "on"},
        ),
    )
    show_result(window, styles, unicode_ok, "import", result)
    return result


def flow_report(window: Any, styles: dict[str, int], unicode_ok: bool, database: Path) -> actions.ActionResult | None:
    values = forms.run_form(
        window,
        styles,
        unicode_ok,
        "write report",
        [
            forms.Field("format", "format", value="markdown", kind="choice",
                        choices=("markdown", "svg", "json", "csv", "html")),
            forms.Field("output", "output", value=str(actions.default_report_path(database, "markdown"))),
        ],
        note=(
            "Markdown lists every inferred link with its rule; SVG draws them dotted; "
            "JSON/CSV/HTML are for sharing without the database."
        ),
    )
    if values is None:
        return None
    report_format = values["format"]

    def write(overwrite: bool = False) -> actions.ActionResult:
        return actions.write_report(
            database, values["output"], report_format=report_format, overwrite=overwrite
        )

    result = run_task(window, styles, unicode_ok, "writing report", write)
    if not result.ok and "exists" in result.message:
        if forms.confirm(window, styles, unicode_ok, "Overwrite the existing report?", detail=values["output"]):
            result = run_task(window, styles, unicode_ok, "writing report", lambda: write(True))
    show_result(window, styles, unicode_ok, "report", result)
    return result


TOOL_ACTIONS = (
    "check database",
    "upgrade schema",
    "rebuild inferred links",
    "merge another copy",
    "discover and save interfaces",
)


def flow_tools(window: Any, styles: dict[str, int], unicode_ok: bool, database: Path) -> actions.ActionResult | None:
    choice = forms.choose(window, styles, unicode_ok, "tools", TOOL_ACTIONS, note="Esc returns to the map")
    if choice is None:
        return None
    label = TOOL_ACTIONS[choice]
    if choice == 0:
        result = run_task(window, styles, unicode_ok, label, lambda: actions.check(database))
    elif choice == 1:
        result = run_task(window, styles, unicode_ok, label, lambda: actions.upgrade(database))
    elif choice == 2:
        result = run_task(window, styles, unicode_ok, label, lambda: actions.rebuild(database))
    elif choice == 3:
        return _flow_merge(window, styles, unicode_ok, database)
    else:
        result = run_task(window, styles, unicode_ok, label, lambda: actions.save_interfaces(database))
    show_result(window, styles, unicode_ok, label, result)
    return result


def _flow_merge(window: Any, styles: dict[str, int], unicode_ok: bool, database: Path) -> actions.ActionResult | None:
    values = forms.run_form(
        window,
        styles,
        unicode_ok,
        "merge another copy",
        [forms.Field("source", "source", value=str(Path.cwd() / "copy.sqlite"))],
        note="The source must belong to the same engagement (same uid).",
    )
    if values is None:
        return None
    preview = run_task(
        window,
        styles,
        unicode_ok,
        "merge preview",
        lambda: actions.merge(database, values["source"], dry_run=True),
    )
    show_result(window, styles, unicode_ok, "merge preview", preview)
    if not preview.ok:
        return preview
    if not forms.confirm(window, styles, unicode_ok, "Apply this merge?", detail=preview.message):
        return None
    result = run_task(
        window,
        styles,
        unicode_ok,
        "merging",
        lambda: actions.merge(database, values["source"]),
    )
    show_result(window, styles, unicode_ok, "merge", result)
    return result


def flow_activity(
    window: Any,
    styles: dict[str, int],
    unicode_ok: bool,
    log: actions.ActivityLog,
) -> None:
    height, width = window.getmaxyx()
    itop, ileft, ih, iw = _box(window, styles, unicode_ok, title="activity log", width=84, height=max(10, height - 4))
    row = itop
    entries = log.entries[-max(1, ih - 3):]
    if not entries:
        safe_addstr(window, row, ileft, "no events yet", iw, _attr(styles, "muted"), unicode_ok=unicode_ok)
    for stamp, severity, message, detail in entries:
        if row >= itop + ih - 2:
            break
        attr = _attr(styles, "error") if severity == "error" else _attr(styles, "text")
        safe_addstr(window, row, ileft, clip(f"{stamp} {severity:<7} {message}", iw), iw, attr, unicode_ok=unicode_ok)
        row += 1
    safe_addstr(
        window, itop + ih - 1, ileft, "w save log   Esc back", iw,
        _attr(styles, "muted"), unicode_ok=unicode_ok,
    )
    window.refresh()
    window.timeout(-1)
    try:
        while True:
            key = window.getch()
            if key == 27:
                return
            if key == ord("w"):
                try:
                    path = log.write_to(Path.cwd() / "lumos-log.txt")
                except OSError:
                    continue
                safe_addstr(
                    window, itop + ih - 1, ileft, clip(f"wrote {path}", iw), iw,
                    _attr(styles, "accent"), unicode_ok=unicode_ok,
                )
                window.refresh()
                window.getch()
                return
    finally:
        window.timeout(1000)
