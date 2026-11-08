"""Curses presentation of a read-only topology snapshot."""

from __future__ import annotations

import curses
import locale
import math
import os
import signal
import sys
from pathlib import Path
from typing import Any

from ..core.text import sanitize_text
from ..services.map_view import MapNode, MapSnapshot, load_map_snapshot, render_plain_snapshot


class TuiError(ValueError):
    """The terminal interface could not be initialized."""


_KIND_GLYPHS = {
    "root": ("@", "◆"),
    "device": ("o", "●"),
    "hop": ("+", "○"),
    "unknown_hop": ("?", "?"),
    "manual": ("M", "▣"),
    "zone": ("Z", "▧"),
}

_EDGE_GLYPHS = {
    "traceroute": ("-", "─"),
    "alternate": ("=", "═"),
    "inferred": (".", "┄"),
    "manual": ("#", "╳"),
    "imported": ("~", "┈"),
}


def _unicode_enabled() -> bool:
    if os.environ.get("LUMOS_ASCII"):
        return False
    encoding = sys.stdout.encoding or locale.getpreferredencoding(False)
    return "utf" in encoding.lower()


def _safe_addstr(window: Any, y: int, x: int, text: str, width: int, attr: int = 0, *, unicode_ok: bool = True) -> None:
    if width <= 0:
        return
    text = sanitize_text(text, max_chars=max(width * 4, 64))
    if not unicode_ok:
        text = text.encode("ascii", "replace").decode("ascii")
    try:
        window.addnstr(y, x, text, width, attr)
    except (curses.error, UnicodeEncodeError):
        try:
            fallback = text.encode("ascii", "replace").decode("ascii")
            window.addnstr(y, x, fallback, width, attr)
        except curses.error:
            pass


def _init_colors() -> dict[str, int]:
    if "NO_COLOR" in os.environ or not curses.has_colors():
        return {"plain": 0, "header": curses.A_BOLD, "selected": curses.A_REVERSE, "edge": 0, "review": curses.A_BOLD}
    try:
        curses.start_color()
        colors = curses.COLORS
        palette = (
            (39, 201, 46, 226, 196, 33)
            if colors >= 256
            else (curses.COLOR_CYAN, curses.COLOR_MAGENTA, curses.COLOR_GREEN,
                  curses.COLOR_YELLOW, curses.COLOR_RED, curses.COLOR_BLUE)
        )
        for pair, color in enumerate(palette, start=1):
            curses.init_pair(pair, color, -1)
        return {
            "plain": 0,
            "header": curses.color_pair(1) | curses.A_BOLD,
            "selected": curses.color_pair(2) | curses.A_BOLD,
            "edge": curses.color_pair(6),
            "review": curses.color_pair(4) | curses.A_BOLD,
            "device": curses.color_pair(3),
            "hop": curses.color_pair(6),
            "manual": curses.color_pair(2),
        }
    except curses.error:
        return {"plain": 0, "header": curses.A_BOLD, "selected": curses.A_REVERSE, "edge": 0, "review": curses.A_BOLD}


def _ring_positions(nodes: tuple[MapNode, ...], width: int, height: int) -> dict[str, tuple[int, int]]:
    if not nodes or width < 4 or height < 3:
        return {}
    root = next((node for node in nodes if node.kind == "root"), nodes[0])
    cx, cy = width // 2, height // 2
    positions = {root.id: (cx, cy)}
    remaining = [node for node in nodes if node.id != root.id]
    groups: dict[int, list[MapNode]] = {}
    for node in remaining:
        groups.setdefault(max(1, node.distance), []).append(node)
    max_distance = max(groups, default=1)
    radius = max(1, min(width // 2 - 2, height // 2 - 2))
    for distance, group in sorted(groups.items()):
        ring = max(2, int(radius * distance / (max_distance + 1)))
        for index, node in enumerate(group):
            angle = (2.0 * math.pi * index / max(1, len(group))) - math.pi / 2.0
            x = max(1, min(width - 2, cx + round(math.cos(angle) * ring * 1.8)))
            y = max(1, min(height - 2, cy + round(math.sin(angle) * ring)))
            positions[node.id] = (x, y)
    return positions


def _raster_line(canvas: list[list[str]], start: tuple[int, int], end: tuple[int, int], glyph: str) -> None:
    x0, y0 = start
    x1, y1 = end
    dx, sx = abs(x1 - x0), 1 if x0 < x1 else -1
    dy, sy = -abs(y1 - y0), 1 if y0 < y1 else -1
    error = dx + dy
    while True:
        if 0 <= y0 < len(canvas) and 0 <= x0 < len(canvas[0]) and canvas[y0][x0] == " ":
            if glyph in {".", "·", "#", "╳", "~", "┄", "┈"}:
                canvas[y0][x0] = glyph
            elif dx == 0:
                canvas[y0][x0] = "|" if glyph.isascii() else "│"
            elif dy == 0:
                canvas[y0][x0] = glyph
            else:
                canvas[y0][x0] = "/" if (x1 - start[0]) * (y1 - start[1]) < 0 else "\\"
        if x0 == x1 and y0 == y1:
            break
        twice = 2 * error
        if twice >= dy:
            error += dy
            x0 += sx
        if twice <= dx:
            error += dx
            y0 += sy


def _draw_map(window: Any, snapshot: MapSnapshot, selected: int, selected_kind: str, unicode_ok: bool, colors: dict[str, int]) -> None:
    height, width = window.getmaxyx()
    window.erase()
    if height < 6 or width < 32:
        _safe_addstr(window, 0, 0, "Terminal too small; resize to at least 32x6", width, curses.A_BOLD, unicode_ok=unicode_ok)
        window.refresh()
        return
    title = f"LUMOS  MAP  |  {snapshot.engagement_name}  |  scans {snapshot.scans}  nodes {len(snapshot.nodes)}  review {snapshot.review_items}"
    _safe_addstr(window, 0, 0, title, width, colors["header"], unicode_ok=unicode_ok)
    _safe_addstr(window, 1, 0, "[Map:m]  [Hosts:v]  ? Help", width, colors["plain"], unicode_ok=unicode_ok)

    details_width = min(34, max(12, width // 3))
    canvas_width = max(8, width - details_width - 4)
    canvas_height = height - 4
    canvas = [[" " for _ in range(canvas_width)] for _ in range(canvas_height)]
    positions = _ring_positions(snapshot.nodes, canvas_width, canvas_height)
    glyph_unicode = unicode_ok
    for edge in snapshot.edges:
        start = positions.get(edge.from_node_id)
        end = positions.get(edge.to_node_id)
        if start is None or end is None:
            continue
        glyphs = _EDGE_GLYPHS.get(edge.edge_type, ("-", "─"))
        _raster_line(canvas, start, end, glyphs[1] if glyph_unicode else glyphs[0])
    for row, line in enumerate(canvas):
        _safe_addstr(window, row + 2, 0, "".join(line), canvas_width, colors["edge"], unicode_ok=unicode_ok)
    selected_node = snapshot.nodes[selected] if selected_kind == "node" and 0 <= selected < len(snapshot.nodes) else None
    selected_edge = snapshot.edges[selected] if selected_kind == "edge" and 0 <= selected < len(snapshot.edges) else None
    for index, node in enumerate(snapshot.nodes):
        point = positions.get(node.id)
        if point is None:
            continue
        x, y = point
        marker = _KIND_GLYPHS.get(node.kind, ("?", "?"))[1 if glyph_unicode else 0]
        prefix = ">" if selected_node is not None and index == selected else " "
        label = sanitize_text(node.label, max_chars=80)
        text = f"{prefix}{marker} {label}"
        _safe_addstr(window, y + 2, max(0, x - min(len(text) // 2, max(0, canvas_width - 1))), text,
                     max(1, canvas_width - max(0, x - min(len(text) // 2, max(0, canvas_width - 1)))),
                     colors["selected"] if selected_node is not None and index == selected else colors.get("device" if node.kind == "device" else "manual" if node.kind in {"manual", "zone"} else "hop", 0),
                     unicode_ok=unicode_ok)
        if node.review_count:
            _safe_addstr(window, y + 2, min(canvas_width - 1, x + 1), "!", colors["review"], unicode_ok=unicode_ok)

    # Show real edge provenance as a compact legend; no line is synthesized for isolated nodes.
    legend = "  ".join(f"{_EDGE_GLYPHS.get(t, ('-', '─'))[1 if unicode_ok else 0]} {t}" for t in sorted({e.edge_type for e in snapshot.edges}))
    if selected_edge is not None:
        legend = f"> selected {selected_edge.edge_type} confidence={selected_edge.confidence:.2f}  " + legend
    if legend:
        _safe_addstr(window, height - 2, 0, legend, canvas_width, colors["edge"], unicode_ok=unicode_ok)
    else:
        _safe_addstr(window, height - 2, 0, "No topology links recorded; isolated nodes are not connected by inference.", canvas_width, colors["plain"], unicode_ok=unicode_ok)

    divider_x = canvas_width + 1
    try:
        for y in range(2, height - 2):
            window.addch(y, divider_x, "|" if not unicode_ok else "│", colors["edge"])
    except curses.error:
        pass
    detail_x = divider_x + 2
    if selected_node is not None:
        _safe_addstr(window, 2, detail_x, "SELECTED", details_width, colors["header"], unicode_ok=unicode_ok)
        _safe_addstr(window, 3, detail_x, f"Type: {selected_node.kind}", details_width, colors["plain"], unicode_ok=unicode_ok)
        _safe_addstr(window, 4, detail_x, selected_node.label, details_width, colors["selected"], unicode_ok=unicode_ok)
        _safe_addstr(window, 6, detail_x, "Addresses", details_width, colors["header"], unicode_ok=unicode_ok)
        for offset, address in enumerate(selected_node.addresses[:max(0, height - 13)]):
            _safe_addstr(window, 7 + offset, detail_x, address, details_width, colors["plain"], unicode_ok=unicode_ok)
        info_y = min(height - 5, 8 + len(selected_node.addresses))
        _safe_addstr(window, info_y, detail_x, f"Open ports: {selected_node.open_ports}", details_width, colors["plain"], unicode_ok=unicode_ok)
        _safe_addstr(window, info_y + 1, detail_x, f"Hop distance: {selected_node.distance}", details_width, colors["plain"], unicode_ok=unicode_ok)
        if selected_node.os_name:
            _safe_addstr(window, info_y + 2, detail_x, f"OS: {selected_node.os_name}", details_width, colors["plain"], unicode_ok=unicode_ok)
        if selected_node.review_count:
            _safe_addstr(window, info_y + 3, detail_x, f"Review flags: {selected_node.review_count}", details_width, colors["review"], unicode_ok=unicode_ok)
    elif selected_edge is not None:
        by_id = {node.id: node for node in snapshot.nodes}
        source = by_id.get(selected_edge.from_node_id)
        destination = by_id.get(selected_edge.to_node_id)
        _safe_addstr(window, 2, detail_x, "EDGE DETAILS", details_width, colors["header"], unicode_ok=unicode_ok)
        _safe_addstr(window, 3, detail_x, selected_edge.edge_type, details_width, colors["selected"], unicode_ok=unicode_ok)
        _safe_addstr(window, 4, detail_x, f"From: {source.label if source else selected_edge.from_node_id}", details_width, colors["plain"], unicode_ok=unicode_ok)
        _safe_addstr(window, 5, detail_x, f"To: {destination.label if destination else selected_edge.to_node_id}", details_width, colors["plain"], unicode_ok=unicode_ok)
        _safe_addstr(window, 7, detail_x, f"Source: {selected_edge.source_kind}", details_width, colors["plain"], unicode_ok=unicode_ok)
        _safe_addstr(window, 8, detail_x, f"Source ID: {selected_edge.source_id or '-'}", details_width, colors["plain"], unicode_ok=unicode_ok)
        _safe_addstr(window, 9, detail_x, f"Confidence: {selected_edge.confidence:.2f}", details_width, colors["plain"], unicode_ok=unicode_ok)
        _safe_addstr(window, 11, detail_x, f"First seen: {selected_edge.first_observed_at or 'unknown'}", details_width, colors["plain"], unicode_ok=unicode_ok)
        _safe_addstr(window, 12, detail_x, f"Last confirmed: {selected_edge.last_confirmed_at or 'not confirmed'}", details_width, colors["plain"], unicode_ok=unicode_ok)
        _safe_addstr(window, 14, detail_x, f"Author: {selected_edge.author or '-'}", details_width, colors["plain"], unicode_ok=unicode_ok)
    navigation = "↑/k/h previous  ↓/j/l next  e edges  n nodes  v Hosts  m Map  / search  r refresh  c root  ? help  q quit" if unicode_ok else "up/k/h previous  down/j/l next  e edges  n nodes  v Hosts  m Map  / search  r refresh  c root  ? help  q quit"
    _safe_addstr(window, height - 1, 0, navigation, width, colors["header"], unicode_ok=unicode_ok)
    window.refresh()


def _draw_hosts(window: Any, snapshot: MapSnapshot, selected: int, unicode_ok: bool, colors: dict[str, int]) -> None:
    height, width = window.getmaxyx()
    window.erase()
    _safe_addstr(window, 0, 0, f"LUMOS  HOSTS  |  {snapshot.engagement_name}", width, colors["header"], unicode_ok=unicode_ok)
    _safe_addstr(window, 1, 0, "[Map:m]  [Hosts:v]  ? Help", width, colors["plain"], unicode_ok=unicode_ok)
    start = max(0, min(selected - (height - 5) // 2, max(0, len(snapshot.nodes) - (height - 4))))
    for index, node in enumerate(snapshot.nodes[start:start + height - 4], start=start):
        prefix = ">" if index == selected else " "
        addresses = ", ".join(node.addresses)
        row = f"{prefix}{node.kind:12} {node.label}  {addresses}  open:{node.open_ports}"
        _safe_addstr(window, 2 + index - start, 0, row, width, colors["selected"] if index == selected else 0, unicode_ok=unicode_ok)
    navigation = "↑/k/h previous  ↓/j/l next  m Map  r refresh  ? help  q quit" if unicode_ok else "up/k/h previous  down/j/l next  m Map  r refresh  ? help  q quit"
    _safe_addstr(window, height - 1, 0, navigation, width, colors["header"], unicode_ok=unicode_ok)
    window.refresh()


def _show_help(window: Any, unicode_ok: bool, colors: dict[str, int]) -> None:
    height, width = window.getmaxyx()
    window.erase()
    for row, text in enumerate((
        "Lumos map prototype - keyboard controls",
        "q       Quit and restore the terminal",
        "UP / k / h      Select previous node",
        "DOWN / j / l    Select next node",
        "v       Show host list",
        "e       Inspect observed topology edges and provenance",
        "n       Return to root/node selection",
        "m       Show map",
        "/       Search node labels and addresses",
        "r       Reload the read-only database snapshot",
        "c       Select the scanner root",
        "?       Return to the map",
        "",
        "Only stored topology_edges are drawn. Disconnected nodes remain unlinked.",
        "Live scanning, saved layout, mouse, and edit actions are not in this slice.",
        "",
        "Press any key to return.",
    )):
        if row < height:
            _safe_addstr(window, row, 1, text, width - 2, colors["header"] if row == 0 else 0, unicode_ok=unicode_ok)
    window.refresh()
    window.getch()


def _run_curses(window: Any, database: Path) -> None:
    window.keypad(True)
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    colors = _init_colors()
    unicode_ok = _unicode_enabled()
    window.timeout(-1)
    snapshot = load_map_snapshot(database)
    selected = 0
    selected_kind = "node"
    view = "map"
    help_screen = False
    while True:
        if help_screen:
            _show_help(window, unicode_ok, colors)
            help_screen = False
        if view == "map":
            _draw_map(window, snapshot, selected, selected_kind, unicode_ok, colors)
        else:
            _draw_hosts(window, snapshot, selected, unicode_ok, colors)
        key = window.getch()
        if key in (ord("q"), 27):
            return
        if key == curses.KEY_RESIZE:
            window.clearok(True)
            continue
        if key == ord("e") and snapshot.edges:
            selected_kind = "edge"
            selected = min(selected, len(snapshot.edges) - 1)
            view = "map"
        elif key == ord("n"):
            selected_kind = "node"
            selected = next((i for i, node in enumerate(snapshot.nodes) if node.kind == "root"), 0)
        elif key in (curses.KEY_UP, curses.KEY_LEFT, ord("k"), ord("h")):
            count = len(snapshot.edges) if selected_kind == "edge" else len(snapshot.nodes)
            selected = max(0, selected - 1)
            selected = min(selected, max(0, count - 1))
        elif key in (curses.KEY_DOWN, curses.KEY_RIGHT, ord("j"), ord("l")):
            count = len(snapshot.edges) if selected_kind == "edge" else len(snapshot.nodes)
            selected = min(max(0, count - 1), selected + 1)
        elif key == ord("m"):
            view = "map"
        elif key == ord("v"):
            selected_kind = "node"
            selected = min(selected, max(0, len(snapshot.nodes) - 1))
            view = "hosts"
        elif key == ord("r"):
            snapshot = load_map_snapshot(database)
            if selected_kind == "edge" and not snapshot.edges:
                selected_kind = "node"
            count = len(snapshot.edges) if selected_kind == "edge" else len(snapshot.nodes)
            selected = min(selected, max(0, count - 1))
        elif key == ord("c"):
            selected_kind = "node"
            selected = next((i for i, node in enumerate(snapshot.nodes) if node.kind == "root"), 0)
            view = "map"
        elif key == ord("?"):
            help_screen = True
        elif key == ord("/"):
            query = ""
            try:
                curses.echo()
                curses.curs_set(1)
                height, width = window.getmaxyx()
                _safe_addstr(window, height - 1, 0, "/", width, colors["header"], unicode_ok=unicode_ok)
                window.refresh()
                query = window.getstr(height - 1, 1, max(1, width - 2)).decode("utf-8", "replace")
            except curses.error:
                pass
            finally:
                curses.noecho()
                try:
                    curses.curs_set(0)
                except curses.error:
                    pass
            needle = sanitize_text(query, max_chars=128).lower()
            found = next((i for i, node in enumerate(snapshot.nodes)
                          if needle and (needle in node.label.lower() or any(needle in addr.lower() for addr in node.addresses))), None)
            if found is not None:
                selected_kind = "node"
                selected = found
                view = "map"


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
