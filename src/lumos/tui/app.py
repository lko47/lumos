"""Curses presentation of a read-only topology snapshot."""

from __future__ import annotations

import curses
import getpass
import locale
import os
import signal
import sys
import time
from pathlib import Path
from typing import Any

from ..core import state as local_state
from ..core.decisions import DecisionError, record_decision
from ..core.text import sanitize_text
from ..services import actions
from ..services.map_view import MapSnapshot, MapSnapshotWatcher, load_map_snapshot, render_plain_snapshot
from . import theme
from . import flows
from .overlays import draw_help, draw_palette
from .widgets import set_backdrop
from .render import (
    ViewState,
    draw_footer,
    draw_header,
    draw_hosts_screen,
    draw_map_screen,
    draw_scans_screen,
)
from .render import draw_map as _draw_map
from .widgets import safe_addstr

MIN_HEIGHT = 8
MIN_WIDTH = 40
VIEWS = ("map", "hosts", "scans")

_COMMANDS: tuple[tuple[str, str, str], ...] = (
    ("map", "show the topology map", "map"),
    ("hosts", "browse host rows", "hosts"),
    ("scans", "scan status history", "scans"),
    ("edges", "select the first observed link", "edges"),
    ("root", "jump to the scanner root", "root"),
    ("refresh", "reload the database snapshot", "refresh"),
    ("theme", "cycle the colour theme", "theme"),
    ("reset", "reset pan and zoom", "reset"),
    ("new", "create a new engagement database", "new"),
    ("open", "open another engagement database", "open"),
    ("scope", "list, add or remove scope rules", "scope"),
    ("scan", "run a scope-checked Nmap scan", "scan"),
    ("import", "import an Nmap XML file", "import"),
    ("report", "write a Markdown or SVG report", "report"),
    ("tools", "check, upgrade, rebuild, merge, interfaces", "tools"),
    ("log", "recent events; w saves them", "log"),
    ("help", "keyboard reference", "help"),
    ("quit", "restore the terminal and exit", "quit"),
)


class TuiError(ValueError):
    """The terminal interface could not be initialized."""


def _unicode_enabled() -> bool:
    if os.environ.get("LUMOS_ASCII"):
        return False
    try:
        encoding = sys.stdout.encoding or locale.getpreferredencoding(False)
    except (AttributeError, ValueError):
        return False
    return "utf" in (encoding or "").lower()


def _initial_theme(capability: str) -> str:
    if capability == theme.CAPABILITY_MONO:
        return "mono"
    requested = os.environ.get("LUMOS_THEME", "").strip().lower()
    return requested if requested in theme.THEMES else "aurora"


def _cycle_theme(current: str, capability: str) -> str:
    if capability == theme.CAPABILITY_MONO:
        return current
    return theme.next_theme(current)


def _set_view(state: ViewState, view: str) -> None:
    state.view = view if view in VIEWS else "map"
    if state.view in {"hosts", "scans"}:
        state.selected_kind = "node"


def _clamp_selection(state: ViewState, snapshot: MapSnapshot) -> None:
    if state.view == "scans":
        state.scan_selected = max(0, min(state.scan_selected, max(0, len(snapshot.scans_detail) - 1)))
        return
    if state.selected_kind == "edge" and not snapshot.edges:
        state.selected_kind = "node"
    count = len(snapshot.edges) if state.selected_kind == "edge" else len(snapshot.nodes)
    state.selected = max(0, min(state.selected, max(0, count - 1)))


def _move_selection(state: ViewState, snapshot: MapSnapshot, delta: int) -> None:
    if state.view == "scans":
        state.scan_selected = max(0, min(state.scan_selected + delta, max(0, len(snapshot.scans_detail) - 1)))
        return
    count = len(snapshot.edges) if state.selected_kind == "edge" else len(snapshot.nodes)
    state.selected = max(0, min(state.selected + delta, max(0, count - 1)))


def _jump_selection(state: ViewState, snapshot: MapSnapshot, *, last: bool) -> None:
    if state.view == "scans":
        state.scan_selected = max(0, len(snapshot.scans_detail) - 1) if last else 0
        return
    count = len(snapshot.edges) if state.selected_kind == "edge" else len(snapshot.nodes)
    state.selected = max(0, count - 1) if last else 0


def _select_root(state: ViewState, snapshot: MapSnapshot) -> None:
    state.selected_kind = "node"
    state.selected = next((index for index, node in enumerate(snapshot.nodes) if node.kind == "root"), 0)
    _set_view(state, "map")


def _select_edges(state: ViewState, snapshot: MapSnapshot) -> None:
    if not snapshot.edges:
        state.notify("No observed links recorded for this engagement")
        return
    state.selected_kind = "edge"
    state.selected = min(state.selected, len(snapshot.edges) - 1)
    _set_view(state, "map")


def _search(snapshot: MapSnapshot, query: str) -> int | None:
    needle = sanitize_text(query, max_chars=128).strip().lower()
    if not needle:
        return None
    for index, node in enumerate(snapshot.nodes):
        if needle in node.label.lower() or any(needle in address.lower() for address in node.addresses):
            return index
    return None


def _draw_frame(
    window: Any,
    snapshot: MapSnapshot,
    state: ViewState,
    styles: dict[str, int],
    unicode_ok: bool,
    theme_name: str,
    capability: str,
) -> None:
    height, width = window.getmaxyx()
    window.erase()
    if height < MIN_HEIGHT or width < MIN_WIDTH:
        safe_addstr(
            window,
            0,
            0,
            f"Terminal too small; resize to at least {MIN_WIDTH}x{MIN_HEIGHT}",
            width,
            styles.get("error", 0),
            unicode_ok=unicode_ok,
        )
        window.refresh()
        return
    draw_header(window, snapshot, state, styles, unicode_ok, theme_name, capability)
    if state.view == "hosts":
        draw_hosts_screen(window, snapshot, state, styles, unicode_ok)
    elif state.view == "scans":
        draw_scans_screen(window, snapshot, state, styles, unicode_ok)
    else:
        draw_map_screen(window, snapshot, state, styles, unicode_ok)
    draw_footer(window, snapshot, state, styles, unicode_ok, time.monotonic())
    window.refresh()


def _prompt(window: Any, label: str, styles: dict[str, int], unicode_ok: bool) -> str:
    height, width = window.getmaxyx()
    if height < 2:
        return ""
    echo_width = max(1, width - len(label) - 1)
    try:
        curses.echo()
        curses.curs_set(1)
        safe_addstr(window, height - 1, 0, label, width, styles.get("accent", 0), unicode_ok=unicode_ok)
        window.refresh()
        raw = window.getstr(height - 1, len(label), echo_width)
        return raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
    except curses.error:
        return ""
    finally:
        curses.noecho()
        try:
            curses.curs_set(0)
        except curses.error:
            pass
        window.timeout(1000)


def _show_help(
    window: Any,
    snapshot: MapSnapshot,
    state: ViewState,
    styles: dict[str, int],
    unicode_ok: bool,
    theme_name: str,
    capability: str,
) -> None:
    window.timeout(-1)
    try:
        _draw_frame(window, snapshot, state, styles, unicode_ok, theme_name, capability)
        draw_help(window, styles, unicode_ok)
        window.refresh()
        window.getch()
    finally:
        window.timeout(1000)


def _pick_command(
    window: Any,
    snapshot: MapSnapshot,
    state: ViewState,
    styles: dict[str, int],
    unicode_ok: bool,
    theme_name: str,
    capability: str,
) -> str | None:
    """Modal command palette; returns the chosen command name or ``None``."""
    query = ""
    index = 0
    window.timeout(-1)
    try:
        while True:
            needle = query.strip().lower()
            entries = [
                (label, description, name)
                for label, description, name in _COMMANDS
                if not needle or needle in label or needle in description.lower()
            ]
            index = max(0, min(index, max(0, len(entries) - 1)))
            _draw_frame(window, snapshot, state, styles, unicode_ok, theme_name, capability)
            draw_palette(window, styles, unicode_ok, query, entries, index)
            window.refresh()
            key = window.getch()
            if key == -1:
                continue
            if key == 27:
                return None
            if key in (10, 13, curses.KEY_ENTER):
                return entries[index][2] if entries else None
            if key in (curses.KEY_BACKSPACE, 8, 127):
                query = query[:-1]
                index = 0
                continue
            if key in (curses.KEY_UP, curses.KEY_PPAGE):
                index = max(0, index - 1)
                continue
            if key in (curses.KEY_DOWN, curses.KEY_NPAGE):
                index = min(max(0, len(entries) - 1), index + 1)
                continue
            if key == 9:  # Tab autocompletes the highlighted label.
                if entries:
                    query = entries[index][0]
                    continue
            if 32 <= key < 127:
                query += chr(key)
                index = 0
    finally:
        window.timeout(1000)


def _run_curses(window: Any, database: Path) -> None:
    window.keypad(True)
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    try:
        # A lone Escape must close overlays immediately instead of waiting out
        # curses' default one-second escape-sequence delay.
        curses.set_escdelay(25)
    except (AttributeError, curses.error):
        pass
    capability = theme.detect_capability()
    theme_name = _initial_theme(capability)
    styles = theme.init_styles(theme_name, capability)
    unicode_ok = _unicode_enabled()
    window.timeout(1000)
    activity = actions.ActivityLog()
    activity.add("info", f"opened {Path(database).name}")
    path = Path(database)
    while True:
        watcher = MapSnapshotWatcher(path, interval=1.0)
        watcher.start()
        try:
            switched = _run_event_loop(
                window, path, watcher, unicode_ok, styles, theme_name, capability, activity
            )
        finally:
            watcher.stop()
        if switched is None:
            return
        path = Path(switched)
        local_state.remember_engagement(path)
        window.keypad(True)
        window.timeout(1000)


def _run_event_loop(
    window: Any,
    database: Path,
    watcher: MapSnapshotWatcher,
    unicode_ok: bool,
    styles: dict[str, int],
    theme_name: str,
    capability: str,
    activity: actions.ActivityLog,
) -> Path | None:
    snapshot = watcher.prime()
    if snapshot is None:
        if watcher.error is not None:
            raise watcher.error
        snapshot = load_map_snapshot(database)
    state = ViewState()
    _clamp_selection(state, snapshot)
    dirty = True
    while True:
        # Modals repaint this frame behind themselves instead of blanking a
        # rectangle, so an open dialog never leaves holes in the map.
        set_backdrop(
            window,
            lambda: _draw_frame(window, snapshot, state, styles, unicode_ok, theme_name, capability),
        )
        if dirty:
            _draw_frame(window, snapshot, state, styles, unicode_ok, theme_name, capability)
            dirty = False
        # Animate only while something is actually moving, and poll quickly
        # while the watcher is rebuilding a snapshot the UI asked for.
        if snapshot.active_scans or state.notify_active() or watcher.pending:
            window.timeout(250)
            dirty = True
        else:
            window.timeout(1000)
        key = window.getch()
        updated = watcher.take_latest()
        if updated is not None:
            snapshot = updated
            _clamp_selection(state, snapshot)
            dirty = True
        if key == -1:
            continue
        dirty = True
        if key == curses.KEY_RESIZE:
            window.clearok(True)
            dirty = True
            continue
        if key in (ord("q"), 27):
            return
        if key == ord("?"):
            _show_help(window, snapshot, state, styles, unicode_ok, theme_name, capability)
            dirty = True
            continue
        if key in (ord("N"), ord("P"), ord("S"), ord("I"), ord("R"), ord("T"), ord("!")):
            action_name = {
                ord("N"): "new",
                ord("P"): "scope",
                ord("S"): "scan",
                ord("I"): "import",
                ord("R"): "report",
                ord("T"): "tools",
                ord("!"): "log",
            }[key]
            switched = _run_command(
                action_name,
                window,
                database,
                state,
                snapshot,
                styles,
                theme_name,
                capability,
                unicode_ok,
                activity,
            )
            if switched is not None:
                return switched
            try:
                watcher.expanded_zone = state.expanded_zone
                watcher.reload_now()
            except Exception:  # keep the last good snapshot
                pass
            dirty = True
            continue

        action: str | None = None
        if key == ord(":"):
            action = _pick_command(window, snapshot, state, styles, unicode_ok, theme_name, capability)
            dirty = True
        elif key == ord("/"):
            query = _prompt(window, "/", styles, unicode_ok)
            found = _search(snapshot, query)
            if found is None:
                state.notify(f"no host matches {sanitize_text(query, max_chars=48)!r}")
            else:
                state.selected_kind = "node"
                state.selected = found
                _set_view(state, "map")
            dirty = True
        elif key in (ord("m"), ord("v"), ord("s")):
            _set_view(state, {ord("m"): "map", ord("v"): "hosts", ord("s"): "scans"}[key])
        elif key == 9:  # Tab cycles the three views.
            current = VIEWS.index(state.view) if state.view in VIEWS else 0
            _set_view(state, VIEWS[(current + 1) % len(VIEWS)])
        elif key in (ord("e"), ord("n")):
            if key == ord("e"):
                _select_edges(state, snapshot)
            else:
                state.selected_kind = "node"
                _set_view(state, "map")
        elif key in (ord("c"), ord("C")):
            _select_root(state, snapshot)
        elif key in (ord("g"), ord("G")):
            _jump_selection(state, snapshot, last=key == ord("G"))
        elif key in (curses.KEY_UP, curses.KEY_LEFT, ord("k"), ord("j")):
            _move_selection(state, snapshot, -1 if key in (curses.KEY_UP, curses.KEY_LEFT, ord("k")) else 1)
        elif key in (curses.KEY_DOWN, curses.KEY_RIGHT, ord("l")):
            _move_selection(state, snapshot, 1)
        elif key == ord("h"):
            _move_selection(state, snapshot, -1)
        elif key in (ord("H"), ord("J"), ord("K"), ord("L")):
            dx = -4 if key == ord("H") else 4 if key == ord("L") else 0
            dy = -2 if key == ord("K") else 2 if key == ord("J") else 0
            height, width = window.getmaxyx()
            state.viewport = state.viewport.pan(dx, dy, width, height)
        elif key in (ord("+"), ord("=")):
            state.viewport = state.viewport.zoom_in()
        elif key == ord("-"):
            state.viewport = state.viewport.zoom_out()
        elif key == ord("0"):
            state.viewport = state.viewport.reset()
        elif key == ord("t"):
            theme_name = _cycle_theme(theme_name, capability)
            styles = theme.init_styles(theme_name, capability)
            state.notify(f"theme {theme_name} — {theme.THEME_DESCRIPTIONS.get(theme_name, '')}")
        elif key in (ord("o"), ord("O")):
            rows = snapshot.nodes
            node = rows[state.selected] if state.selected_kind == "node" and 0 <= state.selected < len(rows) else None
            if key == ord("O") or node is None or node.kind != "zone":
                state.expanded_zone = ""
                state.notify("hubs collapsed")
            elif state.expanded_zone == node.zone_id:
                state.expanded_zone = ""
                state.notify(f"collapsed {node.label}")
            else:
                state.expanded_zone = node.zone_id
                state.notify(f"expanded {node.label}; o again collapses")
            watcher.expanded_zone = state.expanded_zone
            watcher.reload_now()
        elif key == ord("i"):
            state.show_inferred = not state.show_inferred
            state.notify(
                "inferred links shown" if state.show_inferred else "inferred links hidden"
            )
        elif key in (ord("p"), ord("x")) and state.selected_kind == "edge":
            _decide_link(database, state, snapshot, key)
            watcher.reload_now()
        elif key == ord("r"):
            watcher.reload_now()
            state.notify("reloading")
        elif key in (10, 13):
            _set_view(state, "map")
        if action:
            switched = _run_command(
                action,
                window,
                database,
                state,
                snapshot,
                styles,
                theme_name,
                capability,
                unicode_ok,
                activity,
            )
            if switched is not None:
                return switched
            if action == "quit":
                return
            if action in {"theme", "help"}:
                capability = theme.detect_capability()
                if action == "theme":
                    theme_name = _cycle_theme(theme_name, capability)
                    styles = theme.init_styles(theme_name, capability)
                    state.notify(f"theme {theme_name} — {theme.THEME_DESCRIPTIONS.get(theme_name, '')}")
                elif action == "help":
                    _show_help(window, snapshot, state, styles, unicode_ok, theme_name, capability)
            dirty = True
        _clamp_selection(state, snapshot)


def _decide_link(database: Path, state: ViewState, snapshot: MapSnapshot, key: int) -> None:
    """Two-press confirmation: p promotes, x rejects an inferred link."""
    if not (0 <= state.selected < len(snapshot.edges)):
        state.notify("select a link first")
        return
    edge = snapshot.edges[state.selected]
    decision = "promoted" if key == ord("p") else "rejected"
    verb = "promote" if decision == "promoted" else "reject"
    if edge.edge_type != "inferred":
        state.pending = None
        state.notify(f"only inferred links can be {verb}d; this one is {edge.edge_type}")
        return
    if state.pending != (edge.id, decision):
        state.pending = (edge.id, decision)
        state.notify(f"press {'p' if decision == 'promoted' else 'x'} again to {verb} this link")
        return
    state.pending = None
    try:
        record_decision(database, edge.id, decision, author=getpass.getuser())
    except (DecisionError, OSError) as exc:
        state.notify(f"{verb} failed: {exc}")
        return
    state.notify(
        "link promoted to a manual link" if decision == "promoted" else "link rejected; it will stay gone"
    )


def _run_command(
    action: str,
    window: Any,
    database: Path,
    state: ViewState,
    snapshot: MapSnapshot,
    styles: dict[str, int],
    theme_name: str,
    capability: str,
    unicode_ok: bool,
    activity: actions.ActivityLog,
) -> Path | None:
    """Run one palette/key action; returns a database to switch to, if any."""
    if action in VIEWS:
        _set_view(state, action)
    elif action == "edges":
        _select_edges(state, snapshot)
    elif action == "root":
        _select_root(state, snapshot)
    elif action == "refresh":
        state.notify("snapshot reloaded")
    elif action == "new":
        return flows.flow_new_engagement(window, styles, unicode_ok)
    elif action == "open":
        return flows.flow_open_path(window, styles, unicode_ok)
    elif action == "scope":
        result = flows.flow_scope(window, styles, unicode_ok, database)
        if result is not None:
            state.notify(result.message)
            activity.add("info" if result.ok else "error", result.message, result.detail)
    elif action == "scan":
        result = flows.flow_scan(window, styles, unicode_ok, database)
        if result is not None:
            state.notify(result.message)
            activity.add("info" if result.ok else "error", result.message, result.detail)
    elif action == "import":
        result = flows.flow_import(window, styles, unicode_ok, database)
        if result is not None:
            state.notify(result.message)
            activity.add("info" if result.ok else "error", result.message, result.detail)
    elif action == "report":
        result = flows.flow_report(window, styles, unicode_ok, database)
        if result is not None:
            state.notify(result.message)
            activity.add("info" if result.ok else "error", result.message, result.detail)
    elif action == "tools":
        result = flows.flow_tools(window, styles, unicode_ok, database)
        if result is not None:
            state.notify(result.message)
            activity.add("info" if result.ok else "error", result.message, result.detail)
    elif action == "log":
        flows.flow_activity(window, styles, unicode_ok, activity)
    return None


def run_app_on_window(window: Any, database: str | Path) -> None:
    """Run the interface on an existing curses window (used by the start screen)."""
    window.keypad(True)
    _run_curses(window, Path(database))


def run_tui(database: str | Path) -> int:
    """Open curses on a TTY; otherwise render the same snapshot as plain CLI text."""
    path = Path(database)
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print(render_plain_snapshot(load_map_snapshot(path)), end="")
        return 0
    old_sigterm = signal.getsignal(signal.SIGTERM)

    def terminate(signum, frame):
        raise SystemExit(128 + signum)

    try:
        signal.signal(signal.SIGTERM, terminate)
        try:
            curses.wrapper(_run_curses, path)
        except KeyboardInterrupt:
            return 130
        except curses.error as exc:
            raise TuiError(f"could not initialize terminal UI: {exc}") from exc
        return 0
    finally:
        signal.signal(signal.SIGTERM, old_sigterm)
