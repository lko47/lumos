"""Frame chrome and table screens (header, footer, hosts, scan status)."""

from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from typing import Any

from ..core.text import sanitize_text
from ..services.map_view import MapSnapshot
from .layout import Viewport
from .map_render import draw_map_panel, draw_sidebar
from .widgets import (
    clip,
    dash,
    display_width,
    draw_box,
    draw_meter,
    elapsed,
    key_hint,
    pad,
    safe_addstr,
    scan_icon,
    short_time,
    spinner,
    status_icon,
)

_VIEW_ORDER = ("map", "hosts", "scans")
_VIEW_TITLES = {"map": "MAP", "hosts": "HOSTS", "scans": "SCANS"}

_SEPARATOR = "│"
_SEPARATOR_ASCII = "|"

_KIND_STYLE = {
    "root": "root",
    "device": "device",
    "hop": "hop",
    "unknown_hop": "unknown_hop",
    "manual": "manual",
    "zone": "zone",
}


@dataclass
class ViewState:
    view: str = "map"
    selected: int = 0
    selected_kind: str = "node"
    viewport: Viewport = field(default_factory=Viewport)
    scan_selected: int = 0
    message: str = ""
    message_until: float = 0.0
    show_inferred: bool = True
    pending: tuple[str, str] | None = None
    expanded_zone: str = ""

    def notify(self, text: str, seconds: float = 4.0) -> None:
        self.message = sanitize_text(text, max_chars=160)
        self.message_until = time.monotonic() + seconds

    def notify_active(self) -> bool:
        return bool(self.message) and time.monotonic() < self.message_until


@dataclass(frozen=True)
class FrameLayout:
    tab_hits: tuple[tuple[int, int, str], ...]
    map_region: tuple[int, int, int, int] | None


def attr(styles: dict[str, int], name: str, default: int = 0) -> int:
    return styles.get(name, default)


def tab_ranges() -> tuple[tuple[int, int, str], ...]:
    hits: list[tuple[int, int, str]] = []
    x = 1
    for view_name in _VIEW_ORDER:
        label_width = len(view_name) + 2
        hits.append((x, x + label_width, view_name))
        x += label_width + 1
    return tuple(hits)


def draw_header(
    window: Any,
    snapshot: MapSnapshot,
    state: ViewState,
    styles: dict[str, int],
    unicode_ok: bool,
    theme_name: str,
    capability: str,
) -> None:
    _height, width = window.getmaxyx()
    sep = _SEPARATOR if unicode_ok else _SEPARATOR_ASCII
    brand = "◆ LUMOS" if unicode_ok else "* LUMOS"
    view = _VIEW_TITLES.get(state.view, "MAP")
    brand_text = f" {brand} "
    safe_addstr(window, 0, 0, clip(brand_text, width), width, attr(styles, "brand"), unicode_ok=unicode_ok)
    used = display_width(brand_text)
    head = clip(f" {view}  {sep}  {snapshot.engagement_name}  {sep}  ", max(0, width - used),
                unicode_ok=unicode_ok)
    safe_addstr(window, 0, used, head, max(0, width - used), attr(styles, "subtitle"), unicode_ok=unicode_ok)
    used += display_width(head)
    nodes_text = f"nodes {len(snapshot.nodes)}"
    if snapshot.not_shown:
        nodes_text += f" (+{snapshot.not_shown} not shown)"
    stats = (
        f"scans {snapshot.scans}  active {snapshot.active_scans}  "
        f"{nodes_text}  review {snapshot.review_items}"
    )
    remaining = max(0, width - used - 10)
    stats = clip(stats, remaining, unicode_ok=unicode_ok)
    stats_style = attr(styles, "scan_running") if snapshot.active_scans else attr(styles, "accent")
    safe_addstr(window, 0, used, stats, remaining, stats_style, unicode_ok=unicode_ok)
    used += display_width(stats)
    clock = time.strftime("%H:%M:%S")
    if width - used > len(clock) + 2:
        safe_addstr(window, 0, width - len(clock) - 1, clock, len(clock),
                    attr(styles, "muted"), unicode_ok=unicode_ok)

    for start, end, view_name in tab_ranges():
        label = f" {view_name.upper()} "
        style = attr(styles, "tab_active") if view_name == state.view else attr(styles, "tab")
        safe_addstr(window, 1, start, clip(label, end - start), end - start, style, unicode_ok=unicode_ok)
    right = f"theme {theme_name} {sep} {state.viewport.label} {sep} {capability}c"
    if width > display_width(right) + 30:
        safe_addstr(window, 1, width - display_width(right) - 1, right, display_width(right),
                    attr(styles, "muted"), unicode_ok=unicode_ok)


def draw_footer(
    window: Any,
    snapshot: MapSnapshot,
    state: ViewState,
    styles: dict[str, int],
    unicode_ok: bool,
    now: float,
) -> None:
    height, width = window.getmaxyx()
    if height < 3:
        return
    if state.notify_active():
        safe_addstr(window, height - 2, 1, clip(state.message, width - 2, unicode_ok=unicode_ok), width - 2,
                    attr(styles, "warn"), unicode_ok=unicode_ok)
    elif snapshot.active_scans:
        frame = spinner(now, unicode_ok)
        text = (f"{frame} {snapshot.active_scans} scan(s) running "
                f"{dash(unicode_ok)} live updates stream in as hosts commit")
        safe_addstr(window, height - 2, 1, clip(text, width - 2, unicode_ok=unicode_ok), width - 2,
                    attr(styles, "scan_running"), unicode_ok=unicode_ok)
    else:
        legend = (
            "\u2501 local  \u2500 observed  \u2504 likely  \u2570 weak"
            if unicode_ok
            else "= local  - observed  : likely  . weak"
        )
        text = f"Ready. {legend}."
        safe_addstr(window, height - 2, 1, clip(text, width - 2, unicode_ok=unicode_ok), width - 2,
                    attr(styles, "muted"), unicode_ok=unicode_ok)

    hints = (
        ("q", "quit"), ("?", "help"), (":", "palette"), ("m", "map"), ("v", "hosts"),
        ("s", "scans"), ("/", "search"), ("t", "theme"), ("+/-", "zoom"), ("HJKL", "pan"),
        ("0", "reset"), ("o/O", "hub"), ("N", "new"), ("S", "scan"), ("T", "tools"),
    )
    x = 1
    for key, text in hints:
        if x >= width - 2:
            break
        x += key_hint(window, height - 1, x, width - x - 1, key, text, styles,
                     unicode_ok=unicode_ok) + 1


def _too_small(window: Any, styles: dict[str, int], unicode_ok: bool, width: int) -> FrameLayout:
    safe_addstr(window, 0, 0, "Terminal too small; resize to at least 40x8", width,
                attr(styles, "error"), unicode_ok=unicode_ok)
    return FrameLayout((), None)


def draw_map_screen(
    window: Any,
    snapshot: MapSnapshot,
    state: ViewState,
    styles: dict[str, int],
    unicode_ok: bool,
) -> FrameLayout:
    height, width = window.getmaxyx()
    if height < 8 or width < 40:
        return _too_small(window, styles, unicode_ok, width)
    sidebar = max(24, min(38, width // 3))
    map_width = max(10, width - sidebar - 1)
    _projected, region = draw_map_panel(window, snapshot, state, styles, unicode_ok,
                                        2, 0, height - 4, map_width)
    draw_sidebar(window, snapshot, state, styles, unicode_ok,
                 2, map_width, height - 4, sidebar)
    return FrameLayout(tab_ranges(), region)


def draw_hosts_screen(
    window: Any,
    snapshot: MapSnapshot,
    state: ViewState,
    styles: dict[str, int],
    unicode_ok: bool,
) -> FrameLayout:
    height, width = window.getmaxyx()
    if height < 8 or width < 40:
        return _too_small(window, styles, unicode_ok, width)
    itop, ileft, ih, iw = draw_box(
        window, 2, 0, height - 4, width,
        title=f" HOSTS  {len(snapshot.nodes)} ",
        border_attr=attr(styles, "border_focus"), title_attr=attr(styles, "title"),
        unicode_ok=unicode_ok, focused=True,
    )
    widths = (16, min(26, max(14, iw // 3)), min(30, max(12, iw // 4)), 6, 6)
    heading = " ".join(
        pad(cell, width, unicode_ok=unicode_ok)
        for cell, width in zip(("KIND", "LABEL", "ADDRESS", "PORTS", "REVIEW"), widths)
    )
    safe_addstr(window, itop, ileft, clip(heading, iw, unicode_ok=unicode_ok), iw,
                attr(styles, "tab_active"), unicode_ok=unicode_ok)
    visible = max(1, ih - 1)
    start = max(0, min(state.selected - visible // 2, max(0, len(snapshot.nodes) - visible)))
    for offset, node in enumerate(snapshot.nodes[start:start + visible]):
        index = start + offset
        prefix = "▶" if index == state.selected and unicode_ok else ">" if index == state.selected else " "
        row = f"{prefix}{status_icon(node.kind, unicode_ok)} {node.kind}"
        cells = (
            row,
            node.label,
            ", ".join(node.addresses) if node.addresses else dash(unicode_ok),
            str(node.open_ports),
            str(node.review_count) if node.review_count else "·",
        )
        text = " ".join(pad(cell, width, unicode_ok=unicode_ok) for cell, width in zip(cells, widths))
        style_name = "selected" if index == state.selected else _KIND_STYLE.get(node.kind, "label")
        if node.review_count and index != state.selected:
            style_name = "error"
        safe_addstr(window, itop + 1 + offset, ileft, clip(text, iw, unicode_ok=unicode_ok), iw,
                    attr(styles, style_name), unicode_ok=unicode_ok)
    if not snapshot.nodes:
        safe_addstr(window, itop + 1, ileft, "No hosts recorded yet.", iw,
                    attr(styles, "muted"), unicode_ok=unicode_ok)
    return FrameLayout(tab_ranges(), None)


def draw_scans_screen(
    window: Any,
    snapshot: MapSnapshot,
    state: ViewState,
    styles: dict[str, int],
    unicode_ok: bool,
) -> FrameLayout:
    height, width = window.getmaxyx()
    if height < 8 or width < 40:
        return _too_small(window, styles, unicode_ok, width)
    scans = snapshot.scans_detail
    title = f" SCANS  {len(scans)}  active {snapshot.active_scans} "
    itop, ileft, ih, iw = draw_box(
        window, 2, 0, height - 4, width, title=title,
        border_attr=attr(styles, "border_focus"), title_attr=attr(styles, "title"),
        unicode_ok=unicode_ok, focused=True,
    )
    if not scans:
        safe_addstr(window, itop, ileft,
                    "No scans recorded. Run: lumos scan DATABASE TARGET --network NAME",
                    iw, attr(styles, "muted"), unicode_ok=unicode_ok)
        return FrameLayout(tab_ranges(), None)
    state.scan_selected = max(0, min(state.scan_selected, len(scans) - 1))
    visible = max(1, ih - 3)
    start = max(0, min(state.scan_selected - visible // 2, max(0, len(scans) - visible)))
    widths = (4, 9, 10, 6, 9)
    heading = (
        pad("", widths[0], unicode_ok=unicode_ok)
        + pad("ID", widths[1], unicode_ok=unicode_ok)
        + pad("STATUS", widths[2], unicode_ok=unicode_ok)
        + pad("HOSTS", widths[3], unicode_ok=unicode_ok)
        + pad("ELAPSED", widths[4], unicode_ok=unicode_ok)
        + "TARGETS"
    )
    safe_addstr(window, itop, ileft, clip(heading, iw, unicode_ok=unicode_ok), iw,
                attr(styles, "tab_active"), unicode_ok=unicode_ok)
    now = time.monotonic()
    for offset, scan in enumerate(scans[start:start + visible]):
        index = start + offset
        running = scan.status == "running"
        icon = spinner(now, unicode_ok) if running else scan_icon(scan.status, unicode_ok)
        duration = elapsed(scan.started_at, scan.ended_at) + ("…" if running and unicode_ok else "")
        targets = ", ".join(scan.targets[:4]) or dash(unicode_ok)
        text = (
            pad(f" {icon}", widths[0], unicode_ok=unicode_ok)
            + pad(scan.short_id, widths[1], unicode_ok=unicode_ok)
            + pad(scan.status, widths[2], unicode_ok=unicode_ok)
            + pad(str(scan.hosts), widths[3], unicode_ok=unicode_ok)
            + pad(duration, widths[4], unicode_ok=unicode_ok)
            + targets
        )
        selected = index == state.scan_selected
        style_name = "selected" if selected else f"scan_{scan.status}"
        safe_addstr(window, itop + 1 + offset, ileft, clip(text, iw, unicode_ok=unicode_ok), iw,
                    attr(styles, style_name, attr(styles, "label")), unicode_ok=unicode_ok)
        if running and iw > 14:
            progress = 0.15 + 0.7 * (0.5 + 0.5 * math.sin(now * 2.0))
            draw_meter(window, itop + 1 + offset, ileft + iw - 12, 11, progress, styles,
                       unicode_ok=unicode_ok, empty_attr=attr(styles, "muted"))
    detail_row = itop + ih - 1
    if detail_row > itop + min(len(scans), visible) + 1:
        scan = scans[state.scan_selected]
        detail = (
            f"{scan.status}  {scan.short_id}  {scan.operator or 'operator ' + dash(unicode_ok)}  "
            f"if {scan.interface or dash(unicode_ok)}  nmap {scan.nmap_version or dash(unicode_ok)}  "
            f"exit {scan.exit_code if scan.exit_code is not None else dash(unicode_ok)}  "
            f"started {short_time(scan.started_at)}"
        )
        safe_addstr(window, detail_row, ileft, clip(detail, iw, unicode_ok=unicode_ok), iw,
                    attr(styles, "muted"), unicode_ok=unicode_ok)
    return FrameLayout(tab_ranges(), None)


def draw_map(
    window: Any,
    snapshot: MapSnapshot,
    selected: int,
    selected_kind: str,
    unicode_ok: bool,
    colors: dict[str, int],
) -> None:
    """Render a full map frame using pre-resolved colour attributes."""
    window.erase()
    state = ViewState(view="map", selected=selected, selected_kind=selected_kind)
    _height, width = window.getmaxyx()
    sep = _SEPARATOR if unicode_ok else _SEPARATOR_ASCII
    brand = "◆ LUMOS" if unicode_ok else "* LUMOS"
    head = f" {brand}  MAP  {sep}  {snapshot.engagement_name}  {sep}  "
    safe_addstr(window, 0, 0, clip(head, width), width, attr(colors, "header"), unicode_ok=unicode_ok)
    nodes_text = f"nodes {len(snapshot.nodes)}"
    if snapshot.not_shown:
        nodes_text += f" (+{snapshot.not_shown} not shown)"
    stats = (
        f"scans {snapshot.scans}  active {snapshot.active_scans}  "
        f"{nodes_text}  review {snapshot.review_items}"
    )
    if width > display_width(head) + display_width(stats) + 2:
        safe_addstr(window, 0, display_width(head), stats, width - display_width(head),
                    attr(colors, "accent"), unicode_ok=unicode_ok)
    height, width = window.getmaxyx()
    if height >= 8 and width >= 40:
        sidebar = max(24, min(38, width // 3))
        map_width = max(10, width - sidebar - 1)
        draw_map_panel(window, snapshot, state, colors, unicode_ok, 2, 0, height - 4, map_width)
        draw_sidebar(window, snapshot, state, colors, unicode_ok, 2, map_width, height - 4, sidebar)
    window.refresh()
