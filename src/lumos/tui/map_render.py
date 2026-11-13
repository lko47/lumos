"""Topology canvas rendering: braille edges, node labels, detail sidebar."""

from __future__ import annotations

from typing import Any, Iterable

from ..core.decisions import describe_edge
from ..services.map_view import MapSnapshot, edge_class
from .braille import BrailleCanvas
from .layout import compute_layout
from . import animation
from . import mouse
from .widgets import (
    clip,
    dash,
    display_width,
    draw_box,
    draw_meter,
    label_value,
    safe_addstr,
    short_time,
    status_icon,
)


_KIND_GLYPHS = {
    "zone_hub": ("<>", "◇"),
    "gateway": ("o", "○"),
    "root": ("@", "◆"),
    "device": ("o", "●"),
    "hop": ("+", "○"),
    "unknown_hop": ("?", "◌"),
    "manual": ("M", "▣"),
    "zone": ("Z", "▧"),
}

_EDGE_GLYPHS = {
    "local": ("=", "━"),
    "observed": ("-", "─"),
    "alternate": ("=", "═"),
    "likely": (":", "┄"),
    "weak": (".", "╌"),
    "manual": ("#", "╳"),
}

# Overlap precedence: a measurement always wins over a guess.
_EDGE_PRIORITY = ("local", "observed", "alternate", "manual", "likely", "weak")


def _attr(styles: dict[str, int], name: str, default: int = 0) -> int:
    return styles.get(name, default)


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
                canvas[y0][x0] = "|"
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


_LAYOUT_CACHE: dict[tuple, dict[str, tuple[int, int]]] = {}


def _cached_layout(nodes, width: int, height: int) -> dict[str, tuple[int, int]]:
    """Layout is deterministic per node set and panel size, so cache it.

    Redraws (keystrokes, spinner ticks, live refreshes that changed nothing on
    screen) reuse the placement instead of re-hashing every node.
    """
    key = (width, height, tuple((node.id, node.kind, node.distance) for node in nodes))
    cached = _LAYOUT_CACHE.get(key)
    if cached is None:
        cached = compute_layout(nodes, width, height)
        if len(_LAYOUT_CACHE) >= 8:
            _LAYOUT_CACHE.clear()
        _LAYOUT_CACHE[key] = cached
    return cached


def _segment_visible(a: tuple[int, int], b: tuple[int, int], width: int, height: int) -> bool:
    return not (
        (a[0] < -2 and b[0] < -2) or (a[0] > width + 2 and b[0] > width + 2)
        or (a[1] < -2 and b[1] < -2) or (a[1] > height + 2 and b[1] > height + 2)
    )


def _braille_runs(
    layers: dict[str, BrailleCanvas], width: int, height: int
) -> list[list[tuple[int, str, str]]]:
    """Composite overlapping braille layers into coloured per-row runs."""
    masks = {name: canvas.masks() for name, canvas in layers.items()}
    rows: list[list[tuple[int, str, str]]] = []
    for y in range(height):
        runs: list[tuple[int, str, str]] = []
        current_style: str | None = None
        current_text = ""
        current_x = 0
        for x in range(width):
            mask = 0
            style = "traceroute"
            for edge_type in _EDGE_PRIORITY:
                layer = masks.get(edge_type)
                if layer is not None and y < len(layer) and x < len(layer[y]) and layer[y][x]:
                    mask = layer[y][x]
                    style = edge_type
                    break
            char = chr(0x2800 + mask) if mask else " "
            if style != current_style and current_text:
                runs.append((current_x, current_text, current_style or "traceroute"))
                current_text = ""
            if not current_text:
                current_x = x
                current_style = style
            current_text += char
        if current_text:
            runs.append((current_x, current_text, current_style or "traceroute"))
        rows.append(runs)
    return rows


def _ascii_runs(
    layers: dict[str, list[list[str]]], width: int, height: int
) -> list[list[tuple[int, str, str]]]:
    rows: list[list[tuple[int, str, str]]] = []
    for y in range(height):
        runs: list[tuple[int, str, str]] = []
        current_style: str | None = None
        current_text = ""
        current_x = 0
        for x in range(width):
            char = " "
            style = "traceroute"
            for edge_type in _EDGE_PRIORITY:
                layer = layers.get(edge_type)
                if layer is not None and y < len(layer) and x < len(layer[y]) and layer[y][x] != " ":
                    char = layer[y][x]
                    style = edge_type
                    break
            if style != current_style and current_text:
                runs.append((current_x, current_text, current_style or "traceroute"))
                current_text = ""
            if not current_text:
                current_x = x
                current_style = style
            current_text += char
        if current_text:
            runs.append((current_x, current_text, current_style or "traceroute"))
        rows.append(runs)
    return rows


def draw_map_panel(
    window: Any,
    snapshot: MapSnapshot,
    state: Any,
    styles: dict[str, int],
    unicode_ok: bool,
    top: int,
    left: int,
    height: int,
    width: int,
) -> tuple[dict[str, tuple[int, int]], tuple[int, int, int, int]]:
    itop, ileft, ih, iw = draw_box(
        window, top, left, height, width,
        title=(
            f"TOPOLOGY  {len(snapshot.nodes)} nodes  {len(snapshot.edges)} links"
            + (f"  (+{snapshot.not_shown} not shown)" if snapshot.not_shown else "")
        ),
        border_attr=_attr(styles, "border_focus"),
        title_attr=_attr(styles, "title"),
        unicode_ok=unicode_ok,
        focused=True,
    )
    if ih < 2 or iw < 4:
        return {}, (itop, ileft, ih, iw)
    positions = _cached_layout(snapshot.nodes, iw, ih)
    projected = {node_id: state.viewport.project(point, iw, ih) for node_id, point in positions.items()}

    if unicode_ok:
        layers: dict[str, BrailleCanvas] = {}
        for edge in snapshot.edges:
            if not state.show_inferred and edge_class(edge) in {"likely", "weak"}:
                continue
            start = projected.get(edge.from_node_id)
            end = projected.get(edge.to_node_id)
            if start is None or end is None or not _segment_visible(start, end, iw, ih):
                continue
            style_name = edge_class(edge)
            canvas = layers.get(style_name)
            if canvas is None:
                canvas = BrailleCanvas(iw, ih)
                layers[style_name] = canvas
            canvas.draw_line((start[0] * 2 + 1, start[1] * 4 + 2),
                             (end[0] * 2 + 1, end[1] * 4 + 2), style=style_name)
        runs = _braille_runs(layers, iw, ih)
    else:
        grids: dict[str, list[list[str]]] = {}
        for edge in snapshot.edges:
            if not state.show_inferred and edge_class(edge) in {"likely", "weak"}:
                continue
            start = projected.get(edge.from_node_id)
            end = projected.get(edge.to_node_id)
            if start is None or end is None or not _segment_visible(start, end, iw, ih):
                continue
            style_name = edge_class(edge)
            grid = grids.setdefault(style_name, [[" " for _ in range(iw)] for _ in range(ih)])
            _raster_line(grid, start, end, _EDGE_GLYPHS.get(style_name, ("-", "─"))[0])
        runs = _ascii_runs(grids, iw, ih)

    for row, row_runs in enumerate(runs):
        for x, text, edge_type in row_runs:
            if not text.strip():
                continue
            safe_addstr(window, itop + row, ileft + x, text, max(1, iw - x),
                        _attr(styles, f"edge_{edge_type}"), unicode_ok=unicode_ok)

    _draw_flow_dots(window, snapshot, state, projected, styles, (itop, ileft, ih, iw), unicode_ok)
    _draw_ripples(window, state, projected, styles, (itop, ileft, ih, iw), unicode_ok)

    selected_node = snapshot.nodes[state.selected] if (
        state.selected_kind == "node" and 0 <= state.selected < len(snapshot.nodes)
    ) else None
    occupied: dict[int, list[tuple[int, int]]] = {}

    def place(y: int, x: int, width: int) -> int | None:
        """Find a free span on row ``y``; labels never overwrite each other."""
        spans = sorted(occupied.get(y, []))
        for start, end in spans:
            if x < end and x + width > start:
                right = end
                if right + width <= iw and all(right + width <= s or right >= e for s, e in spans):
                    return right
                left = start - width
                if left >= 0 and all(left + width <= s or left >= e for s, e in spans):
                    return left
                return None
        return x

    for index, node in enumerate(snapshot.nodes):
        point = projected.get(node.id)
        if point is None or not (0 <= point[0] < iw and 0 <= point[1] < ih):
            continue
        selected = selected_node is not None and index == state.selected
        prefix = "▶" if selected and unicode_ok else ">" if selected else " "
        if node.kind == "zone" and node.member_count:
            separator = " · " if unicode_ok else " * "
            label = f"{node.label}{separator}{node.member_count}"
        else:
            label = node.label
        marker = _KIND_GLYPHS.get(
            "zone_hub" if node.kind == "zone" else "gateway" if node.placeholder else node.kind,
            ("?", "?"),
        )[1 if unicode_ok else 0]
        label = clip(label, max(4, min(24, iw - 4)), unicode_ok=unicode_ok)
        flag = "!" if node.review_count else ""
        marker_text = f"{prefix}{marker}{flag}"
        text = f"{marker_text} {label}"
        x = max(0, min(iw - 1, point[0] - len(text) // 2))
        placed = place(point[1], x, len(text))
        if placed is None:
            text = marker_text
            x = max(0, min(iw - 1, point[0] - len(marker_text) // 2))
        else:
            x = placed
        occupied.setdefault(point[1], []).append((x, x + len(text)))
        style_name = "selected" if selected else (
            "error" if node.review_count else
            "root" if node.kind == "root" else
            "device" if node.kind == "device" else
            "unknown_hop" if node.kind == "unknown_hop" else
            "manual" if node.kind == "manual" else
            "zone" if node.kind == "zone" else "hop"
        )
        safe_addstr(window, itop + point[1], ileft + x, clip(text, iw - x, unicode_ok=unicode_ok),
                    iw - x, _attr(styles, style_name), unicode_ok=unicode_ok)
        mouse.add(itop + point[1], ileft + x, 1, max(1, len(text)), {"kind": "node", "index": index})
    if not snapshot.nodes:
        safe_addstr(window, itop, ileft, f"No nodes yet {dash(unicode_ok)} run a scan with the CLI.", iw,
                    _attr(styles, "muted"), unicode_ok=unicode_ok)
    return projected, (itop, ileft, ih, iw)


# Links whose direction was measured.  Inferred, manual and imported links are
# never animated: motion is a claim about measured direction.
_FLOW_EDGE_TYPES = frozenset({"traceroute", "observed"})


def _draw_flow_dots(
    window: Any,
    snapshot: Any,
    state: Any,
    projected: dict[str, tuple[int, int]],
    styles: dict[str, int],
    rect: tuple[int, int, int, int],
    unicode_ok: bool,
) -> None:
    """One slow dot per measured link, travelling from -> to (hop order)."""
    if not state.animation:
        return
    itop, ileft, ih, iw = rect
    glyph = animation.FLOW_GLYPH if unicode_ok else animation.FLOW_GLYPH_ASCII
    for edge in snapshot.edges:
        if edge.derived or edge.edge_type not in _FLOW_EDGE_TYPES:
            continue
        start = projected.get(edge.from_node_id)
        end = projected.get(edge.to_node_id)
        if start is None or end is None or not animation.flow_visible(start, end, state.now):
            continue
        x, y = animation.flow_position(start, end, animation.phase_for(edge.id), state.now)
        if 0 <= x < iw and 0 <= y < ih:
            safe_addstr(window, itop + y, ileft + x, glyph, 1,
                        _attr(styles, "flow"), unicode_ok=unicode_ok)


def _draw_ripples(
    window: Any,
    state: Any,
    projected: dict[str, tuple[int, int]],
    styles: dict[str, int],
    rect: tuple[int, int, int, int],
    unicode_ok: bool,
) -> None:
    """Expanding rings around nodes discovered in the latest snapshot."""
    if not state.animation or not state.ripples:
        return
    itop, ileft, ih, iw = rect
    for node_id, started_at in state.ripples.items():
        point = projected.get(node_id)
        if point is None:
            continue
        radius = animation.ripple_radius(started_at, state.now)
        if radius < 0:
            continue
        glyph = animation.ripple_glyph(radius, unicode_ok)
        for x, y in animation.ripple_cells(point, radius):
            if 0 <= x < iw and 0 <= y < ih:
                safe_addstr(window, itop + y, ileft + x, glyph, 1,
                            _attr(styles, "ripple"), unicode_ok=unicode_ok)


def _wrap_ports(ports: Iterable[str], width: int) -> list[str]:
    out: list[str] = []
    current = ""
    for port in ports:
        candidate = f"{current} {port}".strip()
        if display_width(candidate) > width - 1 and current:
            out.append(current)
            current = port
        else:
            current = candidate
    if current:
        out.append(current)
    return out


def draw_sidebar(
    window: Any,
    snapshot: MapSnapshot,
    state: Any,
    styles: dict[str, int],
    unicode_ok: bool,
    top: int,
    left: int,
    height: int,
    width: int,
) -> None:
    title = "SELECTED"
    if state.selected_kind == "edge":
        title = "EDGE"
    elif 0 <= state.selected < len(snapshot.nodes) and snapshot.nodes[state.selected].kind == "root":
        title = "SCANNER ROOT"
    itop, ileft, ih, iw = draw_box(
        window, top, left, height, width, title=f" {title} ",
        border_attr=_attr(styles, "border"), title_attr=_attr(styles, "accent"),
        unicode_ok=unicode_ok,
    )
    if ih < 2 or iw < 4:
        return

    def line(row: int, text: str, style: str = "label") -> None:
        if 0 <= row < ih:
            safe_addstr(window, itop + row, ileft, clip(text, iw, unicode_ok=unicode_ok), iw,
                        _attr(styles, style),
                        unicode_ok=unicode_ok)

    def wrap(text: str, width: int) -> list[str]:
        words, rows, current = text.split(), [], ""
        for word in words:
            candidate = f"{current} {word}".strip()
            if len(candidate) > width and current:
                rows.append(current)
                current = word
            else:
                current = candidate
        if current:
            rows.append(current)
        return rows

    def field(row: int, label: str, value: str, style: str = "value") -> None:
        if 0 <= row < ih:
            label_value(window, itop + row, ileft, iw, label, value, styles,
                        value_style=style, unicode_ok=unicode_ok)

    if state.selected_kind == "edge" and 0 <= state.selected < len(snapshot.edges):
        edge = snapshot.edges[state.selected]
        by_id = {node.id: node for node in snapshot.nodes}
        source = by_id.get(edge.from_node_id)
        destination = by_id.get(edge.to_node_id)
        field(0, "type", edge.edge_type, "accent")
        field(1, "from", source.label if source else edge.from_node_id)
        field(2, "to", destination.label if destination else edge.to_node_id)
        line(4, "CONFIDENCE", "muted")
        draw_meter(window, itop + 5, ileft, iw, edge.confidence, styles,
                   unicode_ok=unicode_ok, empty_attr=_attr(styles, "muted"))
        line(6, f"{edge.confidence:.2f}", "value")
        field(8, "rule", edge.rule or edge.source_kind)
        field(9, "source id", edge.source_id or dash(unicode_ok))
        field(11, "first seen", short_time(edge.first_observed_at))
        field(12, "confirmed", short_time(edge.last_confirmed_at) if edge.last_confirmed_at else "not confirmed")
        field(13, "author", edge.author or dash(unicode_ok))
        if edge.rule:
            sentence = describe_edge(
                edge.rule,
                edge.evidence,
                edge.confidence,
                source_label=source.label if source else "",
                destination_label=destination.label if destination else "",
            )
            line(15, "WHY", "muted")
            rows = wrap(sentence, max(8, iw - 2))[: max(1, min(6, ih - 18))]
            for offset, text in enumerate(rows):
                line(16 + offset, text, "value")
        if edge.edge_type == "inferred":
            hint_row = min(ih - 1, 17 + len(rows))
            line(hint_row, "p promote  x reject", "accent")
        return

    node = snapshot.nodes[state.selected] if 0 <= state.selected < len(snapshot.nodes) else None
    if node is None:
        line(0, "No selection", "muted")
        return
    line(0, f"{status_icon(node.kind, unicode_ok)} {node.kind.upper()}", "accent")
    line(1, node.label, "value")
    row = 3
    line(row, "ADDRESSES", "muted")
    row += 1
    for address in node.addresses[:3] or (dash(unicode_ok),):
        line(row, address, "label")
        row += 1
    if node.os_name:
        field(row, "os", node.os_name)
        row += 1
    if node.kind == "root":
        line(row + 1, "VANTAGE", "muted")
        row += 2
        for interface in snapshot.root_interfaces[:6] or (
            f"not saved {dash(unicode_ok)} lumos interfaces --save",
        ):
            line(row, interface, "label")
            row += 1
        field(row + 1, "scans", str(snapshot.scans))
        field(row + 2, "active", str(snapshot.active_scans),
              "scan_running" if snapshot.active_scans else "value")
        return
    if node.kind == "zone":
        field(row, "members", str(node.member_count))
        expanded = bool(snapshot.expanded_zone) and snapshot.expanded_zone == node.zone_id
        line(row + 2, "O collapse" if expanded else "o expand members", "accent")
        return
    line(row + 1, f"OPEN PORTS  {node.open_ports}", "muted")
    draw_meter(window, itop + row + 2, ileft, iw, min(1.0, node.open_ports / 20.0), styles,
               unicode_ok=unicode_ok, empty_attr=_attr(styles, "muted"))
    row += 3
    if node.ports:
        for ports in _wrap_ports(node.ports, iw)[:6]:
            line(row, ports, "port_open")
            row += 1
    else:
        line(row, "no open ports recorded", "muted")
        row += 1
    if node.review_count:
        field(row + 1, "review", f"{node.review_count} flag(s)", "error")
    field(row + 2, "depth", str(node.distance))
    if node.ttl_hops is not None:
        field(row + 3, "about", f"{node.ttl_hops} hop(s) by TTL")
