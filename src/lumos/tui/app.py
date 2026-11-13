"""Curses presentation of a read-only topology snapshot."""

from __future__ import annotations

import curses
import getpass
import locale
import os
import signal
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..core import state as local_state
from ..core.decisions import DecisionError, record_decision
from ..core.text import sanitize_text
from ..services import actions
from ..services.map_view import MapSnapshot, MapSnapshotWatcher, load_map_snapshot, render_plain_snapshot
from ..services import workspace
from . import theme
from . import flows
from . import animation
from . import mouse
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


def _pan_with_arrow(window: Any, state: ViewState, key: int) -> None:
    """Arrow keys move the map window; j/k/h/l keep moving the selection."""
    height, width = window.getmaxyx()
    step_x = max(4, width // 10)
    step_y = max(2, height // 10)
    if key == curses.KEY_LEFT:
        dx, dy = -step_x, 0
    elif key == curses.KEY_RIGHT:
        dx, dy = step_x, 0
    elif key == curses.KEY_UP:
        dx, dy = 0, -step_y
    else:
        dx, dy = 0, step_y
    state.viewport = state.viewport.pan(dx, dy, width, height)


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


@dataclass(frozen=True)
class UiContext:
    """Everything a key handler needs that is not per-frame state."""

    window: Any
    database: Path
    styles: dict[str, int]
    theme_name: str
    capability: str
    unicode_ok: bool
    activity: actions.ActivityLog
    workspace: tuple[str, ...] = ()


# Keys that open a writable flow; the value is the actions.py command name.
_ACTION_KEYS = {
    ord("N"): "new",
    ord("P"): "scope",
    ord("S"): "scan",
    ord("I"): "import",
    ord("R"): "report",
    ord("T"): "tools",
    ord("!"): "log",
}


def _dispatch_action(
    ctx: UiContext,
    watcher: MapSnapshotWatcher,
    state: ViewState,
    snapshot: MapSnapshot,
    action: str,
) -> Path | None:
    """Run one flow and refresh the map; returns a database path to switch to."""
    switched = _run_command(
        action,
        ctx.window,
        ctx.database,
        state,
        snapshot,
        ctx.styles,
        ctx.theme_name,
        ctx.capability,
        ctx.unicode_ok,
        ctx.activity,
    )
    if switched is not None:
        return switched
    try:
        watcher.expanded_zone = state.expanded_zone
        watcher.reload_now()
    except Exception:  # keep the last good snapshot
        pass
    return None


def _mouse_key(
    window: Any,
    state: ViewState,
    snapshot: MapSnapshot,
    layout: "FrameLayout | None" = None,
) -> int | None:
    """Turn a mouse report into state changes or a synthetic key press.

    Returns a key code when the click should replay a keyboard shortcut, or
    ``None`` when the report was applied directly (drag pan, zoom, tabs, rows).
    """
    event = mouse.read(window)
    if event is None:
        return None
    if event.kind in {"press", "drag", "move", "release"}:
        released = _drag(window, state, event)
        # A press and release without movement is still a click; some
        # terminals report the phases separately instead of BUTTON1_CLICKED.
        return _click(state, released) if released is not None else None
    if event.kind == "scroll":
        _zoom_with_wheel(state, layout, event)
        return None
    if event.kind != "click":
        return None
    return _click(state, event)


def _drag(
    window: Any, state: ViewState, event: "mouse.MouseEvent"
) -> "mouse.MouseEvent | None":
    """Press-drag-release pans the map; a drag never counts as a click.

    Returns the release event when the pointer barely moved, so the caller can
    treat it as a click.
    """
    if event.kind == "press":
        state.drag_origin = (event.x, event.y)
        state.drag_distance = 0
        mouse.watch_motion()
        return None
    if event.kind == "release":
        mouse.stop_motion()
        origin = state.drag_origin
        state.drag_origin = None
        if origin is None:
            return None
        dx, dy = event.x - origin[0], event.y - origin[1]
        if abs(dx) + abs(dy) <= 2:
            return event  # a click, not a drag
        if state.drag_distance == 0:
            # Terminals that report only press and release still get a drag.
            height, width = window.getmaxyx()
            state.viewport = state.viewport.pan(dx, dy, width, height)
        return None
    # "move" arrives when the terminal reports motion without the button bit;
    # while a drag is open it means the same thing as "drag".
    if state.drag_origin is None:
        return None
    last_x, last_y = state.drag_origin
    dx, dy = event.x - last_x, event.y - last_y
    if not (dx or dy):
        return None
    height, width = window.getmaxyx()
    state.viewport = state.viewport.pan(dx, dy, width, height)
    state.drag_origin = (event.x, event.y)
    state.drag_distance += abs(dx) + abs(dy)
    return None


def _zoom_with_wheel(
    state: ViewState, layout: "FrameLayout | None", event: "mouse.MouseEvent"
) -> None:
    """Wheel zooms around the pointer when it is over the map, else the centre."""
    direction = 1 if event.direction < 0 else -1
    region = layout.map_region if layout is not None else None
    if state.view != "map" or region is None:
        state.viewport = (
            state.viewport.zoom_in() if direction > 0 else state.viewport.zoom_out()
        )
        return
    itop, ileft, ih, iw = region
    ax, ay = event.x - ileft - 1, event.y - itop - 1
    if not (0 <= ax < iw and 0 <= ay < ih):
        state.viewport = (
            state.viewport.zoom_in() if direction > 0 else state.viewport.zoom_out()
        )
        return
    state.viewport = state.viewport.zoom_at(ax, ay, iw, ih, direction)


def _click(state: ViewState, event: "mouse.MouseEvent") -> int | None:
    """Apply the hotspot under a click; returns a key to replay when relevant."""
    action = mouse.hit(event.y, event.x)
    if not action:
        return None
    kind = str(action.get("kind", ""))
    if kind == "view":
        _set_view(state, str(action.get("value", "map")))
        return None
    if kind == "node":
        state.selected_kind = "node"
        state.selected = int(action.get("index", 0))
        if not action.get("keep_view"):
            _set_view(state, "map")
        return None
    if kind == "scan":
        state.scan_selected = int(action.get("index", 0))
        if not action.get("keep_view"):
            _set_view(state, "scans")
        return None
    if kind == "key":
        value = str(action.get("value", ""))
        return ord(value[0]) if value else None
    return None


def _track_discovery(state: ViewState, snapshot: MapSnapshot) -> None:
    """Start a ripple for every node that appeared in this snapshot.

    The first snapshot is baseline, not news: a 1000-host engagement must not
    ripple on open.  A sweep that adds more than the storm limit is reported by
    the map itself and animates nothing.
    """
    ids = {node.id for node in snapshot.nodes}
    added = ids - state.known_nodes
    if state.known_nodes and added and not animation.storm(len(added)):
        for node_id in list(added)[: animation.RIPPLE_MAX_ACTIVE]:
            state.ripples[node_id] = state.now
    state.known_nodes = ids
    for node_id, started_at in list(state.ripples.items()):
        if animation.ripple_radius(started_at, state.now) < 0:
            del state.ripples[node_id]


# Edge types that carry a travelling dot (bright for measured, dim otherwise).
_FLOW_TYPES = frozenset({"traceroute", "observed", "inferred", "local"})


def _has_flow(snapshot: MapSnapshot) -> bool:
    """True when the map has at least one link that should be moving."""
    return any(edge.edge_type in _FLOW_TYPES for edge in snapshot.edges)


def _sample_pulse(state: ViewState) -> None:
    """Append one liveness sample per second from a real event counter."""
    if state.now - state.pulse_at < animation.IDLE_SECONDS:
        return
    state.pulse_at = state.now
    delta = max(0, state.pulse_counter - state.pulse_last)
    state.pulse_last = state.pulse_counter
    state.pulse.append(delta)
    del state.pulse[:-animation.PULSE_WIDTH * 2]


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
    mouse.clear()
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
        key = window.getch()
        if mouse.is_mouse(key):
            mouse.read_action(window)  # any click closes, like Escape
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
            if mouse.is_mouse(key):
                _event, action = mouse.read_action(window)
                kind = str((action or {}).get("kind", ""))
                if kind == "palette":
                    return entries[int(action.get("index", 0))][2] if entries else None
                return None
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


def _run_curses(window: Any, database: Path, workspace_paths: tuple[str, ...] = ()) -> None:
    window.keypad(True)
    mouse.enable(window)
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
    extra_members: tuple[str, ...] = tuple(workspace_paths)
    path = Path(database)
    while True:
        watcher = MapSnapshotWatcher(path, interval=1.0)
        watcher.start()
        try:
            context = UiContext(
                window, path, styles, theme_name, capability, unicode_ok, activity,
                tuple(extra_members),
            )
            switched = _run_event_loop(context, watcher)
        finally:
            watcher.stop()
        if switched is None:
            return
        path = Path(switched)
        local_state.remember_engagement(path)
        window.keypad(True)
        window.timeout(1000)


def _workspace_or_file(database: Path, members: list[str]) -> MapSnapshot:
    """One file, or the workspace view when other engagements were added."""
    if not members:
        return load_map_snapshot(database)
    return workspace.load_workspace_snapshot([str(database), *members])


def _pick_workspace_member(
    window: Any, styles: dict[str, int], unicode_ok: bool, database: Path, members: list[str]
) -> str | None:
    """Choose another engagement file to add; the file itself is only read."""
    candidates = []
    for entry in actions.recent_engagements():
        path = str(entry.get("path") or "")
        if not path or path == str(database) or path in members:
            continue
        candidates.append(path)
    if not candidates:
        return None
    labels = [f"{Path(path).stem}   {path}" for path in candidates]
    index = forms.choose(
        window, styles, unicode_ok, "add engagement to workspace", labels,
        note="files stay untouched; shared addresses link the clusters",
    )
    return None if index is None else candidates[index]


def _run_event_loop(ctx: UiContext, watcher: MapSnapshotWatcher) -> Path | None:
    window, database = ctx.window, ctx.database
    styles, unicode_ok = ctx.styles, ctx.unicode_ok
    theme_name, capability = ctx.theme_name, ctx.capability
    members: list[str] = [path for path in ctx.workspace if path != str(database)]
    snapshot = _workspace_or_file(database, members)
    primed = watcher.prime()
    if primed is None and watcher.error is not None:
        raise watcher.error
    state = ViewState()
    _clamp_selection(state, snapshot)
    dirty = True
    layout: FrameLayout | None = None
    while True:
        # Modals repaint this frame behind themselves instead of blanking a
        # rectangle, so an open dialog never leaves holes in the map.
        set_backdrop(
            window,
            lambda: _draw_frame(window, snapshot, state, styles, unicode_ok, theme_name, capability),
        )
        state.now = time.monotonic()
        _track_discovery(state, snapshot)
        _sample_pulse(state)
        if dirty:
            layout = _draw_frame(window, snapshot, state, styles, unicode_ok, theme_name, capability)
            dirty = False
        # Animate only while something is actually moving, and poll quickly
        # while the watcher is rebuilding a snapshot the UI asked for.
        animating = state.animation and bool(
            state.ripples or snapshot.active_scans or _has_flow(snapshot)
        )
        window.timeout(animation.tick_timeout(animating or state.notify_active()))
        if animating or state.notify_active() or watcher.pending:
            dirty = True
        key = window.getch()
        updated = watcher.take_latest()
        if updated is not None:
            snapshot = _workspace_or_file(database, members) if members else updated
            state.pulse_counter += 1
            _clamp_selection(state, snapshot)
            dirty = True
        if key == -1:
            continue
        if key == curses.KEY_MOUSE:
            key = _mouse_key(window, state, snapshot, layout)
            if key is None:
                dirty = True
                _clamp_selection(state, snapshot)
                continue
        dirty = True
        state.pulse_counter += 1
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
        if key in _ACTION_KEYS:
            switched = _dispatch_action(ctx, watcher, state, snapshot, _ACTION_KEYS[key])
            if switched is not None:
                return switched
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
        elif key == ord("w"):
            picked = _pick_workspace_member(window, styles, unicode_ok, database, members)
            if picked is not None:
                members.append(picked)
                snapshot = _workspace_or_file(database, members)
                _clamp_selection(state, snapshot)
                state.notify(f"workspace: {len(members) + 1} engagements")
            dirty = True
        elif key == ord("a"):
            state.animation = not state.animation
            state.ripples.clear()
            state.notify(f"motion {'on' if state.animation else 'off'}")
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
        elif key in (curses.KEY_UP, curses.KEY_DOWN, curses.KEY_LEFT, curses.KEY_RIGHT) and state.view == "map":
            _pan_with_arrow(window, state, key)
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


def run_tui(database: str | Path, workspace: tuple[str, ...] = ()) -> int:
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
            curses.wrapper(_run_curses, path, tuple(workspace))
        except KeyboardInterrupt:
            return 130
        except curses.error as exc:
            raise TuiError(f"could not initialize terminal UI: {exc}") from exc
        return 0
    finally:
        signal.signal(signal.SIGTERM, old_sigterm)
