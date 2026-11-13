"""Centred overlays: keyboard help and the command palette."""

from __future__ import annotations

from typing import Any, Callable, Sequence

from . import mouse
from .widgets import clear_overlays, clip, draw_box, remember_overlay, safe_addstr


def _attr(styles: dict[str, int], name: str, default: int = 0) -> int:
    return styles.get(name, default)


def _centered(width: int, height: int, box_width: int, box_height: int) -> tuple[int, int]:
    return max(0, (height - box_height) // 2), max(0, (width - box_width) // 2)


def _place(window: Any, box_width: int, box_height: int) -> tuple[int, int, int, int]:
    """Clamp an overlay to the terminal so a resize never clips or shifts it off-screen."""
    height, width = window.getmaxyx()
    box_width = max(12, min(box_width, width))
    box_height = max(4, min(box_height, height))
    top, left = _centered(width, height, box_width, box_height)
    clear_overlays(window)
    remember_overlay(window, (top, left, box_height, box_width))
    return top, left, box_height, box_width


def draw_help(window: Any, styles: dict[str, int], unicode_ok: bool) -> None:
    height, width = window.getmaxyx()
    top, left, box_height, box_width = _place(window, min(78, max(30, width - 4)), min(17, max(10, height - 2)))
    itop, ileft, ih, iw = draw_box(
        window, top, left, box_height, box_width, title=" HELP ",
        border_attr=_attr(styles, "border_focus"), title_attr=_attr(styles, "brand"),
        unicode_ok=unicode_ok, focused=True,
    )
    columns: tuple[tuple[tuple[str, tuple[tuple[str, str], ...]], ...], ...]
    if iw >= 76:
        columns = (
            (
                ("Navigate", (
                    ("↑ ↓ / j k", "select node or row"),
                    ("g / G", "first / last"),
                    ("Tab", "cycle map, hosts, scans"),
                    ("Enter", "return to the map"),
                )),
                ("Views", (
                    ("m / v / s", "map, hosts, scan status"),
                    ("e / n", "edges / nodes"),
                    ("c", "jump to scanner root"),
                    ("/", "search labels"),
                )),
            ),
            (
                ("Display", (
                    ("+ / -", "zoom in / out (wheel zooms at the pointer)"),
                    ("H J K L", "pan the map"),
                    ("arrows", "pan the map"),
                    ("drag", "pan the map with the mouse"),
                    ("0", "reset viewport"),
                    ("t", "next colour theme"),
                )),
                ("Links", (
                    ("o / O", "expand / collapse hubs"),
                    ("i", "hide inferred links"),
                    ("p / x", "promote / reject (twice)"),
                    ("e", "select the first link"),
                )),
            ),
            (
                ("Act", (
                    ("N", "new engagement"),
                    ("S", "run a scan"),
                    ("P", "scope rules"),
                    ("I", "import XML"),
                    ("R", "write report"),
                    ("T", "tools"),
                    ("!", "event log"),
                )),
                ("System", (
                    (":", "command palette"),
                    ("r", "reload database"),
                    ("q", "quit"),
                    ("?", "close this help"),
                )),
            ),
        )
    elif iw >= 56:
        # Two columns keep the essential keys readable.
        columns = (
            (
                ("Navigate", (
                    ("↑ ↓ / j k", "select node or row"),
                    ("m / v / s", "map, hosts, scans"),
                    ("e / n", "edges / nodes"),
                    ("/", "search labels"),
                    ("t", "next colour theme"),
                )),
                ("Links", (
                    ("o / O", "expand / collapse hubs"),
                    ("i", "hide inferred links"),
                    ("p / x", "promote / reject (twice)"),
                )),
            ),
            (
                ("Act", (
                    ("N", "new engagement"),
                    ("S", "run a scan"),
                    ("P", "scope rules"),
                    ("I", "import XML"),
                    ("R", "write report"),
                    ("T", "tools"),
                    ("!", "event log"),
                )),
                ("System", (
                    (":", "command palette"),
                    ("r", "reload database"),
                    ("q", "quit"),
                    ("?", "close this help"),
                )),
            ),
        )
    else:
        # Narrow terminals keep the essentials on one column.
        columns = ((
            ("Keys", (
                ("↑ ↓ / j k", "select"),
                ("m / v / s", "map, hosts, scans"),
                ("N / S / T", "new, scan, tools"),
                ("P / I / R", "scope, import, report"),
                ("o / i / p / x", "hubs, inferred, decide"),
                ("/", "search"),
                ("q", "quit"),
            )),
        ),)
    column_width = iw // len(columns) if columns else iw
    for column_index, column in enumerate(columns):
        x = ileft + column_index * column_width
        row = 0
        for heading, entries in column:
            if row >= ih - 2:
                break
            safe_addstr(window, itop + row, x, heading.upper(),
                        max(0, min(column_width - 1, iw - (x - ileft))), _attr(styles, "accent"),
                        unicode_ok=unicode_ok)
            for offset, (key, text) in enumerate(entries, start=1):
                if row + offset >= ih - 2:
                    break
                safe_addstr(window, itop + row + offset, x, f"{key:<10}",
                            min(11, iw - (x - ileft)), _attr(styles, "help_key"),
                            unicode_ok=unicode_ok)
                safe_addstr(window, itop + row + offset, x + 11,
                            clip(text, max(0, column_width - 12)), max(0, column_width - 12),
                            _attr(styles, "help_text"), unicode_ok=unicode_ok)
            row += len(entries) + 2
    mouse.add(top, left, box_height, box_width, {"kind": "close"})
    footer_row = itop + ih - 2
    safe_addstr(window, footer_row, ileft,
                "Links are observed or marked inferred; p/x decide, i hides, o/O hubs.",
                iw, _attr(styles, "muted"), unicode_ok=unicode_ok)
    safe_addstr(window, footer_row + 1, ileft,
                "Press any key to return.", iw, _attr(styles, "accent"), unicode_ok=unicode_ok)


def draw_palette(
    window: Any,
    styles: dict[str, int],
    unicode_ok: bool,
    query: str,
    entries: Sequence[tuple[str, str, Any]],
    index: int,
) -> None:
    height, width = window.getmaxyx()
    top, left, box_height, box_width = _place(
        window, min(66, max(28, width - 4)), min(len(entries) + 3, max(7, height - 4))
    )
    itop, ileft, ih, iw = draw_box(
        window, top, left, box_height, box_width, title=" COMMAND PALETTE ",
        border_attr=_attr(styles, "border_focus"), title_attr=_attr(styles, "brand"),
        unicode_ok=unicode_ok, focused=True,
    )
    if not entries:
        safe_addstr(window, itop, ileft, "No matching command", iw, _attr(styles, "muted"),
                    unicode_ok=unicode_ok)
    for offset, (label, description, _action) in enumerate(entries[: max(1, ih - 1)]):
        selected = offset == index
        style = _attr(styles, "palette_selected") if selected else _attr(styles, "label")
        pointer = "▶" if selected and unicode_ok else ">" if selected else " "
        text = f"{pointer} {label:<22} {description}"
        safe_addstr(window, itop + offset, ileft, clip(text, iw), iw, style, unicode_ok=unicode_ok)
        mouse.add(itop + offset, ileft, 1, iw, {"kind": "palette", "index": offset})
    input_row = itop + ih - 1
    safe_addstr(window, input_row, ileft, "❯ " if unicode_ok else "> ", 2,
                _attr(styles, "accent"), unicode_ok=unicode_ok)
    safe_addstr(window, input_row, ileft + 2, clip(query, iw - 2), iw - 2,
                _attr(styles, "value"), unicode_ok=unicode_ok)
