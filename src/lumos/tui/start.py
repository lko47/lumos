"""Start screen: bare `lumos` with no database chosen yet."""

from __future__ import annotations

import curses
import os
import signal
import sys
from pathlib import Path
from typing import Any

from .. import __version__
from ..core import state
from . import forms, theme
from .flows import flow_new_engagement, flow_open_path, show_result
from .widgets import clip, safe_addstr
from ..services import actions


def _unicode_enabled() -> bool:
    if os.environ.get("LUMOS_ASCII"):
        return False
    try:
        encoding = sys.stdout.encoding or ""
    except (AttributeError, ValueError):
        return False
    return "utf" in (encoding or "").lower()


def _draw(
    window: Any,
    styles: dict[str, int],
    unicode_ok: bool,
    entries: list[dict],
    index: int,
    message: str,
) -> None:
    height, width = window.getmaxyx()
    window.erase()
    title = f"LUMOS {__version__}"
    safe_addstr(window, 1, 3, title, width - 6, styles.get("brand", 0), unicode_ok=unicode_ok)
    safe_addstr(
        window,
        2,
        3,
        "Terminal network mapping over your own Nmap. Authorized use only.",
        width - 6,
        styles.get("muted", 0),
        unicode_ok=unicode_ok,
    )
    row = 4
    safe_addstr(window, row, 3, "Recent engagements", width - 6, styles.get("accent", 0), unicode_ok=unicode_ok)
    row += 1
    if not entries:
        safe_addstr(
            window,
            row,
            5,
            "none yet - press n to create one",
            width - 8,
            styles.get("muted", 0),
            unicode_ok=unicode_ok,
        )
    for position, entry in enumerate(entries):
        if row >= height - 5:
            break
        marker = ">" if position == index else " "
        suffix = "" if entry["exists"] else "  (missing)"
        line = f"{marker} {clip(entry['name'], 28):<28} {clip(entry['path'], width - 40)}{suffix}"
        attr = styles.get("accent", 0) if position == index else styles.get("text", 0)
        safe_addstr(window, row, 3, clip(line, width - 4), width - 4, attr, unicode_ok=unicode_ok)
        row += 1
    if message:
        safe_addstr(window, height - 4, 3, clip(message, width - 6), width - 6, styles.get("error", 0), unicode_ok=unicode_ok)
    safe_addstr(
        window,
        height - 2,
        3,
        "Enter open   n new engagement   o open path   q quit",
        width - 6,
        styles.get("muted", 0),
        unicode_ok=unicode_ok,
    )
    window.refresh()


def _run_start(window: Any) -> None:
    window.keypad(True)
    try:
        curses.curs_set(0)
    except curses.error:
        pass
    try:
        curses.set_escdelay(25)
    except (AttributeError, curses.error):
        pass
    capability = theme.detect_capability()
    theme_name = os.environ.get("LUMOS_THEME", "").strip().lower()
    theme_name = theme_name if theme_name in theme.THEMES else ("mono" if capability == theme.CAPABILITY_MONO else "aurora")
    styles = theme.init_styles(theme_name, capability)
    unicode_ok = _unicode_enabled()
    window.timeout(1000)
    index = 0
    message = ""

    from .app import run_app_on_window  # imported here to avoid a circular import

    while True:
        entries = state.recent_engagements()
        index = max(0, min(index, max(0, len(entries) - 1)))
        _draw(window, styles, unicode_ok, entries, index, message)
        message = ""
        key = window.getch()
        if key == -1:
            continue
        if key in (ord("q"), 27):
            return
        if key in (curses.KEY_UP, ord("k")):
            index = max(0, index - 1)
            continue
        if key in (curses.KEY_DOWN, ord("j")):
            index = min(max(0, len(entries) - 1), index + 1)
            continue
        if key == ord("n"):
            path = flow_new_engagement(window, styles, unicode_ok)
            if path:
                run_app_on_window(window, path)
                index = 0
            continue
        if key == ord("o"):
            path = flow_open_path(window, styles, unicode_ok)
            if path:
                run_app_on_window(window, path)
                index = 0
            continue
        if key in (10, 13, curses.KEY_ENTER):
            if not entries:
                message = "no engagement selected; press n to create one"
                continue
            entry = entries[index]
            if not entry["exists"]:
                message = f"missing: {entry['path']}"
                state.forget_engagement(entry["path"])
                continue
            opened = actions.open_engagement(entry["path"])
            if not opened.ok:
                message = opened.message
                continue
            run_app_on_window(window, Path(opened.payload["path"]))
            index = 0


def run_start_screen() -> int:
    """Open the start screen on a TTY; otherwise explain how to open a database."""
    if not (sys.stdin.isatty() and sys.stdout.isatty()):
        print(
            "lumos: no database selected. Run `lumos PATH` or `lumos` in a terminal, "
            "or set LUMOS_DB.",
            file=sys.stderr,
        )
        return 0
    old_sigterm = signal.getsignal(signal.SIGTERM)

    def terminate(signum, frame):
        raise SystemExit(128 + signum)

    try:
        signal.signal(signal.SIGTERM, terminate)
        curses.wrapper(_run_start)
        return 0
    except KeyboardInterrupt:
        return 130
    finally:
        signal.signal(signal.SIGTERM, old_sigterm)
