"""Centred overlays: keyboard help and the command palette."""

from __future__ import annotations

from typing import Any, Callable, Sequence

from .widgets import clip, draw_box, safe_addstr


def _attr(styles: dict[str, int], name: str, default: int = 0) -> int:
    return styles.get(name, default)


def _centered(width: int, height: int, box_width: int, box_height: int) -> tuple[int, int]:
    return max(0, (height - box_height) // 2), max(0, (width - box_width) // 2)


def draw_help(window: Any, styles: dict[str, int], unicode_ok: bool) -> None:
    height, width = window.getmaxyx()
    box_width = min(78, max(44, width - 8))
    box_height = min(15, max(10, height - 2))
    top, left = _centered(width, height, box_width, box_height)
    itop, ileft, ih, iw = draw_box(
        window, top, left, box_height, box_width, title=" HELP ",
        border_attr=_attr(styles, "border_focus"), title_attr=_attr(styles, "brand"),
        unicode_ok=unicode_ok, focused=True,
    )
    columns: tuple[tuple[tuple[str, tuple[tuple[str, str], ...]], ...], ...]
    if iw >= 60:
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
                    ("/", "search labels and addresses"),
                )),
            ),
            (
                ("Display", (
                    ("+ / -", "zoom in / out"),
                    ("H J K L", "pan the map"),
                    ("0", "reset viewport"),
                    ("t", "next colour theme"),
                )),
                ("System", (
                    (":", "command palette"),
                    ("r", "reload database"),
                    ("q", "quit and restore terminal"),
                    ("?", "close this help"),
                )),
            ),
        )
    else:
        # Narrow terminals keep the essentials on one column.
        columns = ((
            ("Keys", (
                ("↑ ↓ / j k", "select node or row"),
                ("m / v / s", "map, hosts, scans"),
                ("e / n", "edges / nodes"),
                ("/", "search"),
                ("t", "next theme"),
                ("q", "quit"),
                ("?", "close this help"),
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
    footer_row = itop + ih - 2
    safe_addstr(window, footer_row, ileft,
                "Only stored links are drawn; disconnected nodes stay unlinked.",
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
    box_width = min(66, max(38, width - 10))
    box_height = min(len(entries) + 3, max(7, height - 4))
    top, left = _centered(width, height, box_width, box_height)
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
    input_row = itop + ih - 1
    safe_addstr(window, input_row, ileft, "❯ " if unicode_ok else "> ", 2,
                _attr(styles, "accent"), unicode_ok=unicode_ok)
    safe_addstr(window, input_row, ileft + 2, clip(query, iw - 2), iw - 2,
                _attr(styles, "value"), unicode_ok=unicode_ok)
