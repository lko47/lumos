"""Small curses widgets shared by the Lumos screens."""

from __future__ import annotations

import curses
import unicodedata
import weakref
from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from ..core.text import sanitize_text

MONO = "mono"


def display_width(text: str) -> int:
    """Approximate terminal columns, counting wide glyphs as two."""
    return sum(2 if unicodedata.east_asian_width(char) in {"W", "F"} else
               0 if unicodedata.combining(char) else 1 for char in text)


def dash(unicode_ok: bool = True) -> str:
    """Placeholder for a missing value that degrades on ASCII terminals."""
    return "—" if unicode_ok else "-"


def clip(text: str, width: int, *, unicode_ok: bool = True) -> str:
    """Clip to ``width`` columns, adding an ellipsis when truncated."""
    if width <= 0:
        return ""
    text = sanitize_text(text, max_chars=max(width * 4, 32)).replace("\n", " ").replace("\t", " ")
    if display_width(text) <= width:
        return text
    ellipsis = "…" if unicode_ok else "~"
    budget = max(0, width - 1)
    out: list[str] = []
    used = 0
    for char in text:
        step = display_width(char)
        if used + step > budget:
            break
        out.append(char)
        used += step
    return "".join(out) + ellipsis


def pad(text: str, width: int, *, unicode_ok: bool = True) -> str:
    text = clip(text, width, unicode_ok=unicode_ok)
    return text + " " * max(0, width - display_width(text))


def safe_addstr(
    window: Any,
    y: int,
    x: int,
    text: str,
    width: int,
    attr: int = 0,
    *,
    unicode_ok: bool = True,
) -> None:
    """Write sanitized text, tolerating the bottom-right corner and encodings."""
    if width <= 0 or y < 0 or x < 0:
        return
    text = sanitize_text(text, max_chars=max(width * 4, 64))
    if not unicode_ok:
        text = text.encode("ascii", "replace").decode("ascii")
    try:
        window.addnstr(y, x, text, width, attr)
    except (curses.error, UnicodeEncodeError):
        try:
            window.addnstr(y, x, text.encode("ascii", "replace").decode("ascii"), width, attr)
        except curses.error:
            pass


def hline(window: Any, y: int, x: int, width: int, attr: int, *, unicode_ok: bool = True) -> None:
    """Draw a horizontal rule, clipped to the window when possible."""
    if width <= 0:
        return
    char = "─" if unicode_ok else "-"
    try:
        window.addnstr(y, x, char * width, width, attr)
    except curses.error:
        pass


def fit_box(
    window: Any,
    width: int,
    height: int,
    *,
    margin: int = 2,
    min_width: int = 24,
    min_height: int = 6,
) -> tuple[int, int, int, int] | None:
    """Centre a box of at most ``width``x``height`` inside the window.

    Returns ``(top, left, height, width)`` clamped so the frame never runs past
    the terminal edge, or ``None`` when the terminal is too small for a modal.
    """
    total_height, total_width = window.getmaxyx()
    if total_width < min_width or total_height < min_height:
        return None
    box_width = max(min_width, min(width, total_width - margin))
    box_height = max(min_height, min(height, total_height - margin))
    left = max(0, min((total_width - box_width) // 2, total_width - box_width))
    top = max(0, min((total_height - box_height) // 2, total_height - box_height))
    return top, left, box_height, box_width


# Track drawn rectangles per window: weakly for test doubles, by id for the
# real curses window, which has neither __dict__ nor a weak reference.
_REGIONS_WEAK: "weakref.WeakKeyDictionary[Any, list[tuple[int, int, int, int]]]" = (
    weakref.WeakKeyDictionary()
)
_REGIONS_BY_ID: dict[int, list[tuple[int, int, int, int]]] = {}


_BACKDROPS: dict[int, Callable[[], None]] = {}


def set_backdrop(window: Any, paint: Callable[[], None] | None) -> None:
    """Register the call that repaints the screen behind a modal.

    With a backdrop the modal repaints the real frame instead of blanking
    rectangles, so the map, its borders and the side panel stay intact while a
    dialog is open.
    """
    if paint is None:
        _BACKDROPS.pop(id(window), None)
    else:
        _BACKDROPS[id(window)] = paint


def _regions(window: Any) -> list[tuple[int, int, int, int]]:
    try:
        return _REGIONS_WEAK.setdefault(window, [])
    except TypeError:
        return _REGIONS_BY_ID.setdefault(id(window), [])


def clear_region(window: Any, rect: tuple[int, int, int, int]) -> None:
    """Blank a rectangle so a redrawn or moved modal leaves no ghosts behind."""
    total_height, total_width = window.getmaxyx()
    top, left, height, width = rect
    left = max(0, min(left, total_width - 1))
    width = min(width, total_width - left)
    if height <= 0 or width <= 0:
        return
    blank = " " * width
    for row in range(top, min(top + height, total_height)):
        safe_addstr(window, row, left, blank, width)


def clear_overlays(window: Any) -> None:
    """Erase every rectangle a modal drew earlier, then forget them.

    Modals are layered one at a time; without this a form that grows by a row
    (or a terminal resize that re-centres it) leaves the previous frame on
    screen and the boxes end up overlapping.
    """
    paint = _BACKDROPS.get(id(window))
    if paint is not None:
        _regions(window).clear()
        paint()
        return
    for rect in _regions(window):
        clear_region(window, rect)
    _regions(window).clear()


def remember_overlay(window: Any, rect: tuple[int, int, int, int]) -> None:
    _regions(window).append(rect)


def draw_box(
    window: Any,
    top: int,
    left: int,
    height: int,
    width: int,
    *,
    title: str = "",
    border_attr: int = 0,
    title_attr: int = 0,
    unicode_ok: bool = True,
    focused: bool = False,
    clear: bool = True,
) -> tuple[int, int, int, int]:
    """Draw a framed panel and return the inner ``(top, left, height, width)``.

    The rectangle is blanked first, so a panel redrawn over older content never
    leaves stale borders or text behind.
    """
    if height < 2 or width < 2:
        return (top, left, 0, 0)
    if clear:
        clear_region(window, (top, left, height, width))
    if unicode_ok:
        tl, tr, bl, br, hz, vt = "╭", "╮", "╰", "╯", "─", "│"
    else:
        tl = tr = bl = br = "+"
        hz, vt = "-", "|"
    attr = border_attr
    safe_addstr(window, top, left, tl + hz * max(0, width - 2) + tr, width, attr, unicode_ok=unicode_ok)
    for row in range(top + 1, top + height - 1):
        safe_addstr(window, row, left, vt, 1, attr, unicode_ok=unicode_ok)
        safe_addstr(window, row, left + width - 1, vt, 1, attr, unicode_ok=unicode_ok)
    safe_addstr(window, top + height - 1, left, bl + hz * max(0, width - 2) + br, width, attr, unicode_ok=unicode_ok)
    if title and width > 4:
        label = f" {clip(title, width - 6, unicode_ok=unicode_ok)} "
        safe_addstr(window, top, left + 2, label, width - 4, title_attr or attr, unicode_ok=unicode_ok)
    return (top + 1, left + 1, height - 2, width - 2)


def draw_meter(
    window: Any,
    y: int,
    x: int,
    width: int,
    ratio: float,
    styles: Mapping[str, int],
    *,
    unicode_ok: bool = True,
    empty_attr: int = 0,
) -> None:
    """Draw a btop-style gradient meter with partial block characters."""
    if width <= 0:
        return
    ratio = max(0.0, min(1.0, float(ratio)))
    full = "█" if unicode_ok else "#"
    partials = ("", "▏", "▎", "▍", "▌", "▋", "▊", "▉") if unicode_ok else ("", ".", ":", ":", "+", "+", "*", "*")
    exact = ratio * width
    whole = int(exact)
    remainder = exact - whole
    for column in range(width):
        style = styles.get(f"meter_{min(4, column * 5 // max(1, width))}", 0)
        if column < whole:
            safe_addstr(window, y, x + column, full, 1, style, unicode_ok=unicode_ok)
        elif column == whole and remainder > 0:
            char = partials[min(len(partials) - 1, int(remainder * 8))]
            safe_addstr(window, y, x + column, char or full, 1, style, unicode_ok=unicode_ok)
        else:
            safe_addstr(window, y, x + column, "·" if unicode_ok else ".", 1, empty_attr, unicode_ok=unicode_ok)


def label_value(
    window: Any,
    y: int,
    x: int,
    width: int,
    label: str,
    value: str,
    styles: Mapping[str, int],
    *,
    value_style: str = "value",
    unicode_ok: bool = True,
) -> None:
    """Write ``label  value`` with the label dimmed and the value emphasised."""
    if width <= 0:
        return
    label_text = pad(label, min(11, max(4, width // 3)), unicode_ok=unicode_ok)
    safe_addstr(window, y, x, label_text, width, styles.get("muted", 0), unicode_ok=unicode_ok)
    used = min(width, len(label_text))
    remaining = width - used
    if remaining <= 0:
        return
    safe_addstr(window, y, x + used, clip(value, remaining, unicode_ok=unicode_ok), remaining,
                styles.get(value_style, 0), unicode_ok=unicode_ok)


def key_hint(window: Any, y: int, x: int, width: int, key: str, text: str,
             styles: Mapping[str, int], *, unicode_ok: bool = True) -> int:
    """Write ``key text`` and return the columns consumed."""
    if width <= 0:
        return 0
    key_text = f" {key} "
    safe_addstr(window, y, x, key_text[:width], min(width, len(key_text)), styles.get("tab_active", 0),
                unicode_ok=unicode_ok)
    used = min(width, len(key_text))
    remaining = width - used
    if remaining <= 1:
        return used
    body = clip(text, remaining - 1, unicode_ok=unicode_ok)
    safe_addstr(window, y, x + used, body, remaining, styles.get("tab", 0), unicode_ok=unicode_ok)
    return used + display_width(body)


def status_icon(kind: str, unicode_ok: bool = True) -> str:
    if not unicode_ok:
        return {"root": "@", "device": "o", "hop": "+", "unknown_hop": "?", "manual": "M", "zone": "Z"}.get(kind, "?")
    return {"root": "◆", "device": "●", "hop": "○", "unknown_hop": "◌", "manual": "▣", "zone": "▧"}.get(kind, "·")


def scan_icon(status: str, unicode_ok: bool = True) -> str:
    if not unicode_ok:
        return {"running": "*", "completed": "+", "failed": "x", "cancelled": "-", "queued": "."}.get(status, "?")
    return {"running": "⟳", "completed": "✔", "failed": "✖", "cancelled": "⊘", "queued": "◷"}.get(status, "·")


def short_time(value: str) -> str:
    """Format a stored UTC timestamp for a narrow detail column."""
    if not value:
        return "—"
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return clip(value, 19, unicode_ok=False)
    return parsed.astimezone().strftime("%Y-%m-%d %H:%M")


def elapsed(started_at: str, ended_at: str = "") -> str:
    """Human-readable elapsed time for a stored scan."""
    try:
        start = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        end = datetime.fromisoformat(ended_at.replace("Z", "+00:00")) if ended_at else datetime.now(timezone.utc)
    except ValueError:
        return "?"
    seconds = max(0, int((end - start).total_seconds()))
    if seconds < 60:
        return f"{seconds}s"
    minutes, seconds = divmod(seconds, 60)
    if minutes < 60:
        return f"{minutes}m{seconds:02d}s"
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h{minutes:02d}m"


def spinner(now: float, unicode_ok: bool = True) -> str:
    """Animated progress glyph; deterministic for a given monotonic time."""
    if not unicode_ok:
        return ("*", "+", "x", "-")[int(now * 4) % 4]
    frames = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    return frames[int(now * 8) % len(frames)]
