"""Mouse support: hotspot registry, event decoding and click routing.

Every frame records the rectangles the user can click while it draws them, so
the click handler never has to re-derive the layout. Registration is
last-writer-wins: a dialog drawn after the frame covers the frame's hotspots,
which is exactly the stacking order the user sees.

AV Rule 207 (no unencapsulated global data) is deviated from deliberately:
curses draws on one thread and a dialog must be able to see the same registry
the frame used, so a single :class:`HitRegistry` instance is exposed through
module functions. Nothing else in the module holds state.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

# AV Rule 151: no bare numeric literals; these name the curses mouse masks.
_MOUSE_BUTTON1 = 1
_MOUSE_BUTTON4 = 4
_MOUSE_BUTTON5 = 5
_MIN_HEIGHT = 1
_MIN_WIDTH = 1


@dataclass(frozen=True)
class Hotspot:
    """A clickable rectangle plus the action a click on it should run."""

    top: int
    left: int
    height: int
    width: int
    action: dict[str, Any]

    def contains(self, y: int, x: int) -> bool:
        return (
            self.top <= y < self.top + self.height
            and self.left <= x < self.left + self.width
        )


@dataclass
class MouseEvent:
    """One decoded terminal mouse report."""

    kind: str  # "click" or "scroll"
    y: int
    x: int
    direction: int = 0  # -1 up, +1 down for scroll events


@dataclass
class HitRegistry:
    """Ordered rectangles for the frame currently on screen."""

    _spots: list[Hotspot] = field(default_factory=list)

    def clear(self) -> None:
        self._spots.clear()

    def add(self, top: int, left: int, height: int, width: int, action: dict[str, Any]) -> None:
        if height < _MIN_HEIGHT or width < _MIN_WIDTH:
            return
        self._spots.append(Hotspot(top, left, height, width, action))

    def hit(self, y: int, x: int) -> dict[str, Any] | None:
        """Return the action of the topmost rectangle covering ``(y, x)``."""
        for spot in reversed(self._spots):
            if spot.contains(y, x):
                return spot.action
        return None

    def spots(self) -> Iterable[Hotspot]:
        return tuple(self._spots)


_REGISTRY = HitRegistry()


def clear() -> None:
    """Forget every hotspot; called at the start of each frame."""
    _REGISTRY.clear()


def add(top: int, left: int, height: int, width: int, action: dict[str, Any]) -> None:
    """Record a clickable rectangle for the frame being drawn."""
    _REGISTRY.add(top, left, height, width, action)


def spots() -> tuple[Hotspot, ...]:
    """Every rectangle registered for the current frame, oldest first."""
    return tuple(_REGISTRY.spots())


def hit(y: int, x: int) -> dict[str, Any] | None:
    return _REGISTRY.hit(y, x)


def enable(window: Any) -> bool:
    """Turn on button and wheel reporting; returns False when unsupported."""
    import curses

    try:
        curses.mousemask(curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION)
        window.keypad(True)
    except curses.error:
        return False
    return True


def decode(state: int, x: int, y: int) -> MouseEvent | None:
    """Translate a ``curses`` mouse state into a click or a scroll."""
    import curses

    if state & curses.BUTTON1_CLICKED or state & curses.BUTTON1_PRESSED:
        return MouseEvent("click", y, x)
    if state & curses.BUTTON4_PRESSED:
        return MouseEvent("scroll", y, x, -1)
    if state & curses.BUTTON5_PRESSED:
        return MouseEvent("scroll", y, x, 1)
    return None


def is_mouse(key: int) -> bool:
    """True when ``key`` is curses' mouse pseudo-key."""
    import curses

    return key == curses.KEY_MOUSE


def read_action(window: Any) -> tuple[MouseEvent | None, dict[str, Any] | None]:
    """Read one mouse report and resolve it against the current hotspots."""
    event = read(window)
    if event is None:
        return None, None
    return event, _REGISTRY.hit(event.y, event.x)


def read(window: Any) -> MouseEvent | None:
    """Read one pending mouse report from ``window``."""
    import curses

    try:
        _id, x, y, _z, state = curses.getmouse()
    except curses.error:
        return None
    return decode(state, x, y)
