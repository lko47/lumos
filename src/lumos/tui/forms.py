"""Modal form helpers for the terminal interface (text, toggles, choices)."""

from __future__ import annotations

import curses
from dataclasses import dataclass
from typing import Any, Callable, Sequence
import textwrap

from . import mouse
from .widgets import (
    clear_overlays,
    clear_region,
    draw_box,
    remember_overlay,
    safe_addstr,
)

CONTROL_HINT = "Enter save   Tab next   Esc cancel"
CONTROL_HINT_BOOL = "Space toggle   Enter save   Esc cancel"
MIN_MODAL_WIDTH = 26
MIN_MODAL_HEIGHT = 8


def _wrap(text: str, width: int, *, max_lines: int = 6) -> list[str]:
    """Wrap a note or error so a long phrase stays readable on a narrow terminal."""
    if not text:
        return []
    lines: list[str] = []
    for paragraph in text.splitlines() or [""]:
        wrapped = textwrap.wrap(
            paragraph,
            width=max(8, width),
            break_long_words=True,
            break_on_hyphens=False,
            replace_whitespace=True,
        ) or [""]
        lines.extend(wrapped)
    return lines[:max_lines]


def _clamp(
    height: int, width: int, top: int, left: int, box_height: int, box_width: int
) -> tuple[int, int, int, int]:
    """Keep a modal fully inside the terminal after a resize."""
    box_height = max(4, min(box_height, height))
    box_width = max(8, min(box_width, width))
    top = max(0, min(top, height - box_height))
    left = max(0, min(left, width - box_width))
    return top, left, box_height, box_width


def _too_small(window: Any, styles: dict[str, int], unicode_ok: bool) -> bool:
    height, width = window.getmaxyx()
    if height >= MIN_MODAL_HEIGHT and width >= MIN_MODAL_WIDTH:
        return False
    message = f"terminal too small for a dialog ({width}x{height})"
    safe_addstr(window, 0, 0, message, max(1, width), _attr(styles, "error"), unicode_ok=unicode_ok)
    window.refresh()
    return True


@dataclass
class Field:
    key: str
    label: str
    value: str = ""
    kind: str = "text"  # text | bool | choice
    choices: tuple[str, ...] = ()
    hint: str = ""


def _attr(styles: dict[str, int], name: str, default: int = 0) -> int:
    return styles.get(name, default)


def _field_text(field: Field, active: bool) -> str:
    if field.kind == "bool":
        mark = "[x]" if field.value in {"1", "true", "yes", "on"} else "[ ]"
        return f"{mark} {field.hint or 'enabled'}"
    if field.kind == "choice":
        return f"< {field.value or (field.choices[0] if field.choices else '')} >"
    caret = "_" if active else ""
    shown = field.value if len(field.value) <= 40 else "…" + field.value[-39:]
    return f"{shown}{caret}"


def _draw(
    window: Any,
    styles: dict[str, int],
    unicode_ok: bool,
    *,
    title: str,
    fields: Sequence[Field],
    active: int,
    note: str,
    error: str,
    busy: str = "",
) -> None:
    if _too_small(window, styles, unicode_ok):
        return
    height, width = window.getmaxyx()
    box_width = min(76, max(24, width - 2))
    inner = max(8, box_width - 4)
    note_lines = _wrap(note, inner)
    error_lines = _wrap(error, inner)
    rows_needed = len(fields) + 1 + len(note_lines) + len(error_lines) + (1 if busy else 0) + 3
    box_height = min(rows_needed, max(8, height - 2))
    clear_overlays(window)
    top = max(0, (height - box_height) // 2)
    left = max(0, (width - box_width) // 2)
    top, left, box_height, box_width = _clamp(height, width, top, left, box_height, box_width)
    remember_overlay(window, (top, left, box_height, box_width))
    # A one-cell ring is blanked before the box is drawn, so a map label can
    # never run into the frame and read as if it were inside the dialog.
    clear_region(window, (top - 2, left - 2, box_height + 4, box_width + 4))
    itop, ileft, ih, iw = draw_box(
        window,
        top,
        left,
        box_height,
        box_width,
        title=f" {title} ",
        border_attr=_attr(styles, "border_focus"),
        title_attr=_attr(styles, "brand"),
        unicode_ok=unicode_ok,
        focused=True,
    )
    row = itop
    label_width = min(18, max((len(field.label) for field in fields), default=8) + 1)
    for index, field in enumerate(fields):
        if row >= itop + ih:
            break
        marker = "›" if unicode_ok else ">"
        label = f"{marker if index == active else ' '} {field.label:<{label_width}}"
        attr = _attr(styles, "accent") if index == active else _attr(styles, "muted")
        safe_addstr(window, row, ileft, label, iw, attr, unicode_ok=unicode_ok)
        safe_addstr(
            window,
            row,
            ileft + len(label),
            _field_text(field, index == active),
            max(1, iw - len(label)),
            _attr(styles, "text"),
            unicode_ok=unicode_ok,
        )
        mouse.add(row, ileft, 1, iw, {"kind": "field", "index": index})
        row += 1
    row += 1
    for line in note_lines:
        if row >= itop + ih - 1:
            break
        safe_addstr(window, row, ileft, line, iw, _attr(styles, "muted"), unicode_ok=unicode_ok)
        row += 1
    for line in error_lines:
        if row >= itop + ih - 1:
            break
        safe_addstr(window, row, ileft, line, iw, _attr(styles, "error"), unicode_ok=unicode_ok)
        row += 1
    if busy and row < itop + ih:
        safe_addstr(window, row, ileft, busy, iw, _attr(styles, "accent"), unicode_ok=unicode_ok)
        row += 1
    hint = CONTROL_HINT_BOOL if any(field.kind == "bool" for field in fields) else CONTROL_HINT
    safe_addstr(
        window,
        itop + ih - 1,
        ileft,
        hint,
        iw,
        _attr(styles, "muted"),
        unicode_ok=unicode_ok,
    )
    _register_controls(itop + ih - 1, ileft, iw)
    window.refresh()


def _register_controls(row: int, left: int, width: int) -> None:
    """Make the dialog's Save and Cancel affordances clickable.

    Mirrors the drawn hint line: "Enter save ... Esc cancel".
    """
    span = max(1, width // 2)
    mouse.add(row, left, 1, span, {"kind": "submit"})
    mouse.add(row, left + span, 1, max(1, width - span), {"kind": "cancel"})


def run_form(
    window: Any,
    styles: dict[str, int],
    unicode_ok: bool,
    title: str,
    fields: Sequence[Field],
    *,
    note: str = "",
    validate: Callable[[dict[str, str]], str | None] | None = None,
    busy: str = "",
) -> dict[str, str] | None:
    """Edit fields until Enter submits; returns values or ``None`` on Escape."""
    fields = list(fields)
    active = 0
    error = ""
    window.timeout(-1)
    try:
        while True:
            _draw(
                window,
                styles,
                unicode_ok,
                title=title,
                fields=fields,
                active=active,
                note=note,
                error=error,
                busy=busy,
            )
            key = window.getch()
            if key == -1:
                continue
            if mouse.is_mouse(key):
                _event, action = mouse.read_action(window)
                if action is None:
                    continue
                kind = str(action.get("kind", ""))
                if kind == "field":
                    active = int(action.get("index", 0)) % max(1, len(fields))
                    error = ""
                    continue
                if kind == "cancel":
                    return None
                if kind == "submit":
                    key = 10
                else:
                    continue
            if key == 27:
                return None
            if key in (curses_keys.ENTER):
                values = {field.key: field.value for field in fields}
                message = validate(values) if validate else None
                if message:
                    error = message
                    continue
                return values
            if key in (9, curses_keys.DOWN) or key == 2:  # Tab, down, ^B
                active = (active + 1) % len(fields)
                error = ""
                continue
            if key in (curses_keys.BACKTAB, curses_keys.UP):  # shift-tab, up
                active = (active - 1) % len(fields)
                error = ""
                continue
            field = fields[active]
            if field.kind == "bool" and key in (32, 10, 13):
                field.value = "0" if field.value in {"1", "true", "yes", "on"} else "1"
                continue
            if field.kind == "choice" and key in (
                curses_keys.LEFT,
                curses_keys.RIGHT,
                32,
            ):
                choices = list(field.choices) or [field.value]
                try:
                    index = choices.index(field.value)
                except ValueError:
                    index = 0
                step = -1 if key == curses_keys.LEFT else 1
                field.value = choices[(index + step) % len(choices)]
                continue
            if field.kind == "text":
                if key in (curses_keys.BACKSPACE, 8, 127):
                    field.value = field.value[:-1]
                    continue
                if 32 <= key < 127:
                    field.value = (field.value + chr(key))[:512]
                    continue
    finally:
        window.timeout(1000)


class curses_keys:
    """Numeric key codes, resolved lazily so this module imports without curses."""

    import curses as _curses

    UP = _curses.KEY_UP
    DOWN = _curses.KEY_DOWN
    LEFT = _curses.KEY_LEFT
    RIGHT = _curses.KEY_RIGHT
    ENTER = (10, 13, _curses.KEY_ENTER)
    BACKSPACE = _curses.KEY_BACKSPACE
    BACKTAB = getattr(_curses, "KEY_BTAB", 353)


def confirm(
    window: Any,
    styles: dict[str, int],
    unicode_ok: bool,
    question: str,
    *,
    detail: str = "",
) -> bool:
    """Single-key yes/no; ``n`` or Escape refuses."""
    if _too_small(window, styles, unicode_ok):
        return False
    height, width = window.getmaxyx()
    box_width = min(66, max(24, width - 2))
    box_height = 7 if not detail else 8
    top = max(0, (height - box_height) // 2)
    left = max(0, (width - box_width) // 2)
    clear_overlays(window)
    top, left, box_height, box_width = _clamp(height, width, top, left, box_height, box_width)
    remember_overlay(window, (top, left, box_height, box_width))
    itop, ileft, ih, iw = draw_box(
        window,
        top,
        left,
        box_height,
        box_width,
        title=" confirm ",
        border_attr=_attr(styles, "border_focus"),
        title_attr=_attr(styles, "brand"),
        unicode_ok=unicode_ok,
        focused=True,
    )
    for offset, line in enumerate(_wrap(question, iw, max_lines=2)):
        safe_addstr(window, itop + offset, ileft, line, iw, _attr(styles, "text"), unicode_ok=unicode_ok)
    for offset, line in enumerate(_wrap(detail, iw, max_lines=2)):
        row = itop + len(_wrap(question, iw, max_lines=2)) + offset
        if row < itop + ih - 1:
            safe_addstr(window, row, ileft, line, iw, _attr(styles, "muted"), unicode_ok=unicode_ok)
    safe_addstr(
        window,
        itop + ih - 1,
        ileft,
        "y yes   n / Esc no",
        iw,
        _attr(styles, "muted"),
        unicode_ok=unicode_ok,
    )
    mouse.add(itop, ileft, max(1, ih - 1), max(1, iw // 2), {"kind": "yes"})
    mouse.add(itop, ileft + max(1, iw // 2), max(1, ih - 1), max(1, iw // 2), {"kind": "no"})
    window.refresh()
    window.timeout(-1)
    try:
        while True:
            key = window.getch()
            if mouse.is_mouse(key):
                _event, action = mouse.read_action(window)
                kind = str((action or {}).get("kind", ""))
                if kind == "yes":
                    return True
                if kind == "no":
                    return False
                continue
            if key in (ord("y"), ord("Y")):
                return True
            if key in (ord("n"), ord("N"), 27):
                return False
    finally:
        window.timeout(1000)


def choose(
    window: Any,
    styles: dict[str, int],
    unicode_ok: bool,
    title: str,
    options: Sequence[str],
    *,
    note: str = "",
) -> int | None:
    """Pick one option with arrows/``j``/``k``/Enter; ``None`` on Escape."""
    index = 0
    window.timeout(-1)
    try:
        while True:
            if _too_small(window, styles, unicode_ok):
                return None
            height, width = window.getmaxyx()
            box_height = min(len(options) + 5, max(8, height - 2))
            box_width = min(72, max(24, width - 2))
            top = max(0, (height - box_height) // 2)
            left = max(0, (width - box_width) // 2)
            clear_overlays(window)
            top, left, box_height, box_width = _clamp(height, width, top, left, box_height, box_width)
            remember_overlay(window, (top, left, box_height, box_width))
            itop, ileft, ih, iw = draw_box(
                window,
                top,
                left,
                box_height,
                box_width,
                title=f" {title} ",
                border_attr=_attr(styles, "border_focus"),
                title_attr=_attr(styles, "brand"),
                unicode_ok=unicode_ok,
                focused=True,
            )
            row = itop
            for position, option in enumerate(options):
                if row >= itop + ih - 2:
                    break
                marker = "›" if unicode_ok else ">"
                prefix = f"{marker} " if position == index else "  "
                attr = _attr(styles, "accent") if position == index else _attr(styles, "text")
                safe_addstr(window, row, ileft, prefix + option, iw, attr, unicode_ok=unicode_ok)
                mouse.add(row, ileft, 1, iw, {"kind": "option", "index": position})
                row += 1
            if note and itop + ih - 2 >= row:
                safe_addstr(window, itop + ih - 2, ileft, note, iw, _attr(styles, "muted"), unicode_ok=unicode_ok)
            safe_addstr(
                window,
                itop + ih - 1,
                ileft,
                "Enter select   Esc cancel",
                iw,
                _attr(styles, "muted"),
                unicode_ok=unicode_ok,
            )
            window.refresh()
            key = window.getch()
            if key == -1:
                continue
            if mouse.is_mouse(key):
                _event, action = mouse.read_action(window)
                if action is None:
                    continue
                kind = str(action.get("kind", ""))
                if kind == "field":
                    active = int(action.get("index", 0)) % max(1, len(fields))
                    error = ""
                    continue
                if kind == "cancel":
                    return None
                if kind == "submit":
                    key = 10
                else:
                    continue
            if key == 27:
                return None
            if key in curses_keys.ENTER:
                return index
            if key in (curses_keys.UP, ord("k")):
                index = (index - 1) % len(options)
            elif key in (curses_keys.DOWN, ord("j")):
                index = (index + 1) % len(options)
    finally:
        window.timeout(1000)


# --------------------------------------------------------------------------
# Out-of-scope confirmation: a checkbox to prime, then a red confirm button

CHECKBOX_HINT = "Space prime   Enter confirm   Esc cancel"
PRIMED_ATTR = curses.A_REVERSE


def _draw_button(
    window: Any,
    styles: dict[str, int],
    unicode_ok: bool,
    rect: tuple[int, int, int],
    label: str,
    primed: bool,
) -> int:
    """Draw the red confirm button; returns the row count it occupies.

    Unprimed it is a red outline. Primed, the middle row is filled red with
    reversed text so the arming is unmistakable.
    """
    row, left, width = rect
    red = _attr(styles, "error")
    text_attr = (red | PRIMED_ATTR) if primed else red
    hz = "─" if unicode_ok else "-"
    vt = "│" if unicode_ok else "|"
    top = f"╭{hz * max(0, width - 2)}╮" if unicode_ok else f"+{'-' * max(0, width - 2)}+"
    bottom = f"╰{hz * max(0, width - 2)}╯" if unicode_ok else f"+{'-' * max(0, width - 2)}+"
    safe_addstr(window, row, left, top, width, red, unicode_ok=unicode_ok)
    middle = f" {label} ".center(max(1, width - 2))
    safe_addstr(window, row + 1, left, vt, 1, red, unicode_ok=unicode_ok)
    safe_addstr(window, row + 1, left + 1, middle, max(1, width - 2), text_attr, unicode_ok=unicode_ok)
    safe_addstr(window, row + 1, left + width - 1, vt, 1, red, unicode_ok=unicode_ok)
    safe_addstr(window, row + 2, left, bottom, width, red, unicode_ok=unicode_ok)
    mouse.add(row + 1, left, 1, width, {"kind": "button"})
    return 3


def confirm_scope(
    window: Any,
    styles: dict[str, int],
    unicode_ok: bool,
    *,
    title: str,
    lines: Sequence[str],
    checkbox_label: str,
    label: str = "confirm",
) -> bool:
    """Ask for an out-of-scope override: prime a checkbox, then confirm.

    Returns True only when the operator armed the checkbox and pressed the
    button (Enter, or a click on it). Esc and a click elsewhere cancel.
    """
    if _too_small(window, styles, unicode_ok):
        return False
    height, width = window.getmaxyx()
    box_width = min(70, max(30, width - 2))
    inner = max(12, box_width - 4)
    info = [line for text in lines for line in _wrap(text, inner, max_lines=3)]
    box_height = min(len(info) + 9, max(MIN_MODAL_HEIGHT, height - 2))
    primed = False
    shown = ""
    while True:
        clear_overlays(window)
        top, left, box_height, box_width = _clamp(
            height, width, max(0, (height - box_height) // 2), max(0, (width - box_width) // 2),
            box_height, box_width,
        )
        remember_overlay(window, (top, left, box_height, box_width))
        clear_region(window, (top - 2, left - 2, box_height + 4, box_width + 4))
        itop, ileft, ih, iw = draw_box(
            window, top, left, box_height, box_width,
            title=f" {title} ", border_attr=_attr(styles, "border_focus"),
            title_attr=_attr(styles, "brand"), unicode_ok=unicode_ok, focused=True,
        )
        row = itop
        for line in info:
            if row >= itop + ih - 6:
                break
            safe_addstr(window, row, ileft, line, iw, _attr(styles, "text"), unicode_ok=unicode_ok)
            row += 1
        row += 1
        mark = "[x]" if primed else "[ ]"
        box_attr = _attr(styles, "error") if primed else _attr(styles, "muted")
        safe_addstr(window, row, ileft, f"{mark} {checkbox_label}", iw, box_attr, unicode_ok=unicode_ok)
        mouse.add(row, ileft, 1, iw, {"kind": "checkbox"})
        row += 2
        button_width = max(22, min(iw - 2, len(label) + 12))
        button_left = ileft + max(0, (iw - button_width) // 2)
        _draw_button(
            window, styles, unicode_ok, (row, button_left, button_width), label, primed
        )
        hint_row = itop + ih - 1
        safe_addstr(
            window, hint_row, ileft,
            shown or CHECKBOX_HINT, iw,
            _attr(styles, "error") if shown else _attr(styles, "muted"),
            unicode_ok=unicode_ok,
        )
        window.refresh()
        window.timeout(-1)
        key = window.getch()
        if mouse.is_mouse(key):
            _event, action = mouse.read_action(window)
            kind = str((action or {}).get("kind", ""))
            if kind == "checkbox":
                primed = not primed
                shown = ""
            elif kind == "button":
                if primed:
                    return True
                shown = "prime the checkbox first"
            continue
        if key in (27, ord("q")):
            return False
        if key in (ord(" "), ord("c"), ord("C")):
            primed = not primed
            shown = ""
            continue
        if key in (10, 13, curses.KEY_ENTER):
            if primed:
                return True
            shown = "prime the checkbox first"
            continue
