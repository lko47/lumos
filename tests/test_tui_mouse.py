"""Mouse hotspot routing."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lumos.tui import mouse
from lumos.tui.forms import Field, _draw
from lumos.tui.widgets import draw_box

STYLES: dict[str, int] = {}


class GridWindow:
    """A curses window that records coordinates without a terminal."""

    def __init__(self, height: int = 20, width: int = 80) -> None:
        self.height = height
        self.width = width
        self.writes: list[tuple[int, int, str]] = []
        self.timeout_value = 1000

    def getmaxyx(self) -> tuple[int, int]:
        return self.height, self.width

    def addnstr(self, y: int, x: int, text: str, width: int, _attr: int = 0) -> None:
        if y < 0 or y >= self.height or x < 0 or x >= self.width:
            raise AssertionError(f"write outside window at {y},{x}")
        self.writes.append((y, x, text[:width]))

    def refresh(self) -> None:
        pass

    def timeout(self, value: int) -> None:
        self.timeout_value = value


class RegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        mouse.clear()

    def test_topmost_hotspot_wins(self) -> None:
        mouse.add(0, 0, 5, 5, {"kind": "frame"})
        mouse.add(1, 1, 2, 2, {"kind": "dialog"})
        self.assertEqual(mouse.hit(1, 1), {"kind": "dialog"})
        self.assertEqual(mouse.hit(4, 4), {"kind": "frame"})
        self.assertIsNone(mouse.hit(9, 9))

    def test_clear_forgets_previous_frame(self) -> None:
        mouse.add(0, 0, 5, 5, {"kind": "frame"})
        mouse.clear()
        self.assertIsNone(mouse.hit(2, 2))

    def test_zero_sized_rectangles_are_ignored(self) -> None:
        mouse.add(0, 0, 0, 5, {"kind": "bad"})
        self.assertIsNone(mouse.hit(0, 0))

    def test_click_decoding(self) -> None:
        import curses

        event = mouse.decode(curses.BUTTON1_CLICKED, 7, 3)
        self.assertIsNotNone(event)
        assert event is not None
        self.assertEqual((event.kind, event.x, event.y), ("click", 7, 3))
        wheel = mouse.decode(curses.BUTTON4_PRESSED, 1, 2)
        self.assertIsNotNone(wheel)
        assert wheel is not None
        self.assertEqual((wheel.kind, wheel.direction), ("scroll", -1))


class DialogHotspotTests(unittest.TestCase):
    def setUp(self) -> None:
        mouse.clear()

    def test_form_registers_fields_and_controls(self) -> None:
        window = GridWindow(22, 70)
        fields = [Field("targets", "targets"), Field("network", "network")]
        _draw(window, STYLES, True, title="scan", fields=fields, active=0, note="", error="")
        actions = [spot.action["kind"] for spot in mouse.spots()]
        self.assertEqual(actions.count("field"), 2)
        self.assertIn("submit", actions)
        self.assertIn("cancel", actions)
        field_spot = next(spot for spot in mouse.spots() if spot.action["kind"] == "field")
        action = mouse.hit(field_spot.top, field_spot.left)
        self.assertIsNotNone(action)
        assert action is not None
        self.assertEqual(action["index"], 0)

    def test_dialog_covers_the_frame_below(self) -> None:
        window = GridWindow(22, 70)
        mouse.add(0, 0, 22, 70, {"kind": "frame"})
        _draw(window, STYLES, True, title="confirm", fields=[Field("x", "x")],
              active=0, note="", error="")
        spot = next(s for s in mouse.spots() if s.action["kind"] == "field")
        action = mouse.hit(spot.top, spot.left)
        self.assertIsNotNone(action)
        assert action is not None
        self.assertEqual(action["kind"], "field")

    def test_draw_box_registers_nothing_by_itself(self) -> None:
        before = len(mouse.spots())
        draw_box(GridWindow(), 1, 1, 4, 20)
        self.assertEqual(len(mouse.spots()), before)


class HeaderHitTests(unittest.TestCase):
    def test_tabs_are_clickable_at_the_drawn_columns(self) -> None:
        from lumos.tui.render import tab_ranges

        mouse.clear()
        window = GridWindow(30, 100)
        for start, end, view_name in tab_ranges():
            mouse.add(1, start, 1, end - start, {"kind": "view", "value": view_name})
        for start, end, view_name in tab_ranges():
            first = mouse.hit(1, start)
            last = mouse.hit(1, end - 1)
            self.assertIsNotNone(first)
            self.assertIsNotNone(last)
            assert first is not None and last is not None
            self.assertEqual(first["value"], view_name)
            self.assertEqual(last["value"], view_name)
        self.assertIsNone(mouse.hit(2, 0))
        del window


if __name__ == "__main__":
    unittest.main()
