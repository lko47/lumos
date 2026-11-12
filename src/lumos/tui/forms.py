"""Modal form helpers for the terminal interface (text, toggles, choices)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable, Sequence

from .widgets import draw_box, safe_addstr

CONTROL_HINT = "Enter save   Tab next   Esc cancel"
CONTROL_HINT_BOOL = "Space toggle   Enter save   Esc cancel"


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
    height, width = window.getmaxyx()
    box_width = min(76, max(40, width - 6))
    rows_needed = len(fields) + (1 if note else 0) + (1 if error else 0) + (1 if busy else 0) + 5
    box_height = min(max(8, rows_needed), max(8, height - 2))
    top = max(0, (height - box_height) // 2)
    left = max(0, (width - box_width) // 2)
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
        row += 1
    row += 1
    if note and row < itop + ih:
        safe_addstr(window, row, ileft, note, iw, _attr(styles, "muted"), unicode_ok=unicode_ok)
        row += 1
    if error and row < itop + ih:
        safe_addstr(window, row, ileft, error, iw, _attr(styles, "error"), unicode_ok=unicode_ok)
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
    window.refresh()


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
    height, width = window.getmaxyx()
    box_width = min(66, max(36, width - 6))
    box_height = 7 if not detail else 8
    top = max(0, (height - box_height) // 2)
    left = max(0, (width - box_width) // 2)
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
    safe_addstr(window, itop, ileft, question, iw, _attr(styles, "text"), unicode_ok=unicode_ok)
    if detail:
        safe_addstr(window, itop + 1, ileft, detail, iw, _attr(styles, "muted"), unicode_ok=unicode_ok)
    safe_addstr(
        window,
        itop + ih - 1,
        ileft,
        "y yes   n / Esc no",
        iw,
        _attr(styles, "muted"),
        unicode_ok=unicode_ok,
    )
    window.refresh()
    window.timeout(-1)
    try:
        while True:
            key = window.getch()
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
            height, width = window.getmaxyx()
            box_height = min(len(options) + 5, max(8, height - 2))
            box_width = min(72, max(40, width - 6))
            top = max(0, (height - box_height) // 2)
            left = max(0, (width - box_width) // 2)
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
