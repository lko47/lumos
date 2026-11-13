"""Semantic colour themes with 256-, 16-colour, and monochrome degradation.

The UI never hard-codes a terminal colour.  Every call site asks for a
semantic style (``title``, ``device``, ``scan_running``) and the theme layer
resolves it for the terminal actually in use.  ``NO_COLOR`` forces the
monochrome theme regardless of the selected palette.
"""

from __future__ import annotations

import curses
from dataclasses import dataclass

CAPABILITY_MONO = "mono"
CAPABILITY_16 = "16"
CAPABILITY_256 = "256"


@dataclass(frozen=True)
class Style:
    """A semantic style.

    ``fg``/``bg`` are xterm-256 indices; ``fg16``/``bg16`` are the closest
    basic ANSI colour used on 16-colour terminals.  ``attr`` carries
    non-colour curses attributes such as bold or reverse.
    """

    fg: int = -1
    bg: int = -1
    fg16: int = -1
    bg16: int = -1
    attr: int = 0


_B = curses.A_BOLD
_R = curses.A_REVERSE
_D = curses.A_DIM


def _s(fg: int, fg16: int, *, bg: int = -1, bg16: int = -1, attr: int = 0) -> Style:
    return Style(fg=fg, bg=bg, fg16=fg16, bg16=bg16, attr=attr)


# --- palettes ---------------------------------------------------------------
# "aurora" is the btop-like default: deep cyan borders, bright headings,
# magenta accents, and a warm meter gradient.

_AURORA = {
    "brand": _s(213, curses.COLOR_MAGENTA, attr=_B),
    "title": _s(51, curses.COLOR_CYAN, attr=_B),
    "subtitle": _s(250, curses.COLOR_WHITE),
    "accent": _s(45, curses.COLOR_CYAN),
    "border": _s(240, curses.COLOR_BLUE),
    "border_focus": _s(45, curses.COLOR_CYAN, attr=_B),
    "label": _s(250, curses.COLOR_WHITE),
    "value": _s(255, curses.COLOR_WHITE, attr=_B),
    "muted": _s(244, curses.COLOR_BLUE),
    "ok": _s(46, curses.COLOR_GREEN, attr=_B),
    "warn": _s(220, curses.COLOR_YELLOW, attr=_B),
    "error": _s(203, curses.COLOR_RED, attr=_B),
    "selected": _s(232, curses.COLOR_BLACK, bg=45, bg16=curses.COLOR_CYAN, attr=_B),
    "tab_active": _s(16, curses.COLOR_BLACK, bg=45, bg16=curses.COLOR_CYAN, attr=_B),
    "tab": _s(244, curses.COLOR_BLUE),
    "root": _s(220, curses.COLOR_YELLOW, attr=_B),
    "device": _s(51, curses.COLOR_CYAN, attr=_B),
    "hop": _s(111, curses.COLOR_BLUE),
    "unknown_hop": _s(203, curses.COLOR_RED, attr=_B),
    "manual": _s(213, curses.COLOR_MAGENTA),
    "zone": _s(141, curses.COLOR_MAGENTA),
    "edge_traceroute": _s(39, curses.COLOR_CYAN),
    "edge_alternate": _s(45, curses.COLOR_CYAN),
    "edge_inferred": _s(244, curses.COLOR_BLUE),
    "edge_local": _s(231, curses.COLOR_WHITE),
    "edge_likely": _s(111, curses.COLOR_BLUE),
    "edge_weak": _s(240, curses.COLOR_BLUE),
    "edge_manual": _s(213, curses.COLOR_MAGENTA),
    "edge_imported": _s(141, curses.COLOR_MAGENTA),
    "edge_local": _s(231, curses.COLOR_WHITE),
    "edge_likely": _s(105, curses.COLOR_BLUE),
    "edge_weak": _s(245, curses.COLOR_BLUE),
    "scan_running": _s(220, curses.COLOR_YELLOW, attr=_B),
    "scan_completed": _s(46, curses.COLOR_GREEN),
    "scan_failed": _s(203, curses.COLOR_RED, attr=_B),
    "scan_cancelled": _s(214, curses.COLOR_YELLOW),
    "scan_queued": _s(244, curses.COLOR_BLUE),
    "meter_0": _s(46, curses.COLOR_GREEN),
    "meter_1": _s(118, curses.COLOR_GREEN),
    "meter_2": _s(226, curses.COLOR_YELLOW),
    "meter_3": _s(214, curses.COLOR_YELLOW),
    "meter_4": _s(203, curses.COLOR_RED, attr=_B),
    "help_key": _s(45, curses.COLOR_CYAN, attr=_B),
    "help_text": _s(250, curses.COLOR_WHITE),
    "palette_selected": _s(232, curses.COLOR_BLACK, bg=213, bg16=curses.COLOR_MAGENTA, attr=_B),
    "port_open": _s(46, curses.COLOR_GREEN),
}

_EMBER = {
    **_AURORA,
    "brand": _s(208, curses.COLOR_RED, attr=_B),
    "title": _s(214, curses.COLOR_YELLOW, attr=_B),
    "accent": _s(208, curses.COLOR_RED),
    "border": _s(238, curses.COLOR_RED),
    "border_focus": _s(214, curses.COLOR_YELLOW, attr=_B),
    "selected": _s(232, curses.COLOR_BLACK, bg=214, bg16=curses.COLOR_YELLOW, attr=_B),
    "tab_active": _s(16, curses.COLOR_BLACK, bg=214, bg16=curses.COLOR_YELLOW, attr=_B),
    "device": _s(180, curses.COLOR_YELLOW),
    "hop": _s(173, curses.COLOR_RED),
    "manual": _s(210, curses.COLOR_MAGENTA),
    "zone": _s(137, curses.COLOR_MAGENTA),
    "edge_traceroute": _s(208, curses.COLOR_RED),
    "edge_alternate": _s(214, curses.COLOR_YELLOW),
    "edge_manual": _s(210, curses.COLOR_MAGENTA),
    "edge_imported": _s(137, curses.COLOR_MAGENTA),
    "palette_selected": _s(232, curses.COLOR_BLACK, bg=208, bg16=curses.COLOR_RED, attr=_B),
}

_MATRIX = {
    **_AURORA,
    "brand": _s(40, curses.COLOR_GREEN, attr=_B),
    "title": _s(46, curses.COLOR_GREEN, attr=_B),
    "accent": _s(40, curses.COLOR_GREEN),
    "border": _s(22, curses.COLOR_GREEN),
    "border_focus": _s(46, curses.COLOR_GREEN, attr=_B),
    "selected": _s(16, curses.COLOR_BLACK, bg=46, bg16=curses.COLOR_GREEN, attr=_B),
    "tab_active": _s(16, curses.COLOR_BLACK, bg=46, bg16=curses.COLOR_GREEN, attr=_B),
    "device": _s(47, curses.COLOR_GREEN, attr=_B),
    "hop": _s(34, curses.COLOR_GREEN),
    "manual": _s(118, curses.COLOR_GREEN),
    "zone": _s(65, curses.COLOR_GREEN),
    "edge_traceroute": _s(40, curses.COLOR_GREEN),
    "edge_alternate": _s(46, curses.COLOR_GREEN),
    "edge_manual": _s(118, curses.COLOR_GREEN),
    "edge_imported": _s(65, curses.COLOR_GREEN),
    "edge_local": _s(15, curses.COLOR_WHITE),
    "edge_likely": _s(75, curses.COLOR_BLUE),
    "edge_weak": _s(66, curses.COLOR_BLUE),
    "help_key": _s(46, curses.COLOR_GREEN, attr=_B),
    "palette_selected": _s(16, curses.COLOR_BLACK, bg=46, bg16=curses.COLOR_GREEN, attr=_B),
}

# Monochrome keeps hierarchy through weight and inversion only.
_MONO = {
    name: Style(attr=(_R if name in {"selected", "tab_active", "palette_selected"} else
                      _B if name in {"brand", "title", "root", "device", "unknown_hop", "ok",
                                     "warn", "error", "scan_running", "scan_failed", "help_key"} else
                      _D if name in {"muted", "subtitle", "border", "tab", "scan_queued",
                                     "edge_inferred"} else 0))
    for name in _AURORA
}

THEMES: dict[str, dict[str, Style]] = {
    "aurora": _AURORA,
    "ember": _EMBER,
    "matrix": _MATRIX,
    "mono": _MONO,
}

THEME_ORDER = ("aurora", "ember", "matrix")
THEME_DESCRIPTIONS = {
    "aurora": "cyan and magenta",
    "ember": "warm oranges",
    "matrix": "green phosphor",
    "mono": "no colour",
}


def next_theme(current: str) -> str:
    """Return the next cyclable theme (mono is selected only by NO_COLOR)."""
    if current not in THEME_ORDER:
        return THEME_ORDER[0]
    return THEME_ORDER[(THEME_ORDER.index(current) + 1) % len(THEME_ORDER)]


# Tokens used by the animated layer (packet dots, ripples, liveness strip).
# A palette may name them explicitly; otherwise they are derived from an
# existing token, so every theme — including mono — stays consistent without
# duplicating colour choices.
_DERIVED_STYLES = {"flow": "accent", "ripple": "muted", "pulse": "ok"}


def resolved_styles(theme: str, capability: str) -> dict[str, tuple[int, int, int]]:
    """Resolve a theme to ``(fg, bg, attr)`` triples without touching curses.

    This is the testable core of the colour layer: 16-colour output never
    contains a 256-colour index, and monochrome output never sets one.
    """
    palette = dict(THEMES.get(theme, _AURORA))
    for name, source in _DERIVED_STYLES.items():
        if name not in palette and source in palette:
            palette[name] = palette[source]
    resolved: dict[str, tuple[int, int, int]] = {}
    for name, style in palette.items():
        if capability == CAPABILITY_MONO:
            resolved[name] = (-1, -1, style.attr)
        elif capability == CAPABILITY_16:
            resolved[name] = (style.fg16, style.bg16, style.attr)
        else:
            resolved[name] = (style.fg, style.bg, style.attr)
    return resolved


def detect_capability() -> str:
    """Detect the terminal's colour capability after ``start_color``."""
    import os

    if os.environ.get("NO_COLOR"):
        return CAPABILITY_MONO
    try:
        if not curses.has_colors():
            return CAPABILITY_MONO
        return CAPABILITY_256 if curses.COLORS >= 256 else CAPABILITY_16
    except curses.error:
        return CAPABILITY_MONO


def init_styles(theme: str, capability: str) -> dict[str, int]:
    """Initialise curses colour pairs and return semantic attributes."""
    styles: dict[str, int] = {}
    if capability == CAPABILITY_MONO:
        return {name: attr for name, (_fg, _bg, attr) in resolved_styles(theme, capability).items()}
    try:
        curses.start_color()
        try:
            curses.use_default_colors()
        except curses.error:
            pass
        if int(getattr(curses, "COLOR_PAIRS", 0)) < len(THEMES.get(theme, _AURORA)) + 1:
            return {name: attr for name, (_fg, _bg, attr) in resolved_styles(theme, CAPABILITY_MONO).items()}
        pair = 1
        for name, (fg, bg, attr) in resolved_styles(theme, capability).items():
            curses.init_pair(pair, fg, bg)
            styles[name] = curses.color_pair(pair) | attr
            pair += 1
        return styles
    except curses.error:
        return {name: attr for name, (_fg, _bg, attr) in resolved_styles(theme, CAPABILITY_MONO).items()}
