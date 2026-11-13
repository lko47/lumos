"""Panning: keyboard, wheel anchoring and mouse drag."""

from __future__ import annotations

import unittest
from dataclasses import dataclass

from lumos.tui.app import _drag, _pan_with_arrow, _zoom_with_wheel
from lumos.tui.layout import ZOOM_LEVELS, Viewport
from lumos.tui.render import FrameLayout
from lumos.tui.mouse import MouseEvent


@dataclass
class SizedWindow:
    height: int = 30
    width: int = 100

    def getmaxyx(self) -> tuple[int, int]:
        return self.height, self.width


class ViewportZoomTests(unittest.TestCase):
    def test_zoom_keeps_the_world_point_under_the_anchor(self) -> None:
        view = Viewport()
        width, height = 80, 40
        anchor = (20, 10)
        before = view.unproject(anchor, width, height)
        zoomed = view.zoom_at(anchor[0], anchor[1], width, height, 1)
        after = zoomed.unproject(anchor, width, height)
        self.assertLessEqual(abs(after[0] - before[0]), 1)
        self.assertLessEqual(abs(after[1] - before[1]), 1)
        self.assertGreater(zoomed.zoom, view.zoom)

    def test_zoom_at_clamps_at_both_ends(self) -> None:
        view = Viewport(zoom=ZOOM_LEVELS[-1])
        self.assertEqual(view.zoom_at(0, 0, 40, 20, 1).zoom, ZOOM_LEVELS[-1])
        lowest = Viewport(zoom=ZOOM_LEVELS[0])
        self.assertEqual(lowest.zoom_at(0, 0, 40, 20, -1).zoom, ZOOM_LEVELS[0])

    def test_label_reports_pan_only_when_moved(self) -> None:
        self.assertEqual(Viewport().label, "zoom 1.00x")
        self.assertIn("pan +4,-2", Viewport(pan_x=4, pan_y=-2).label)

    def test_zoom_levels_reach_the_deep_end(self) -> None:
        self.assertGreaterEqual(max(ZOOM_LEVELS), 4.0)
        view = Viewport()
        for _ in range(len(ZOOM_LEVELS) + 3):
            view = view.zoom_in()
        self.assertEqual(view.zoom, ZOOM_LEVELS[-1])


class ArrowPanTests(unittest.TestCase):
    def test_arrows_move_the_viewport_ten_percent(self) -> None:
        import curses

        window = SizedWindow(height=30, width=100)
        state = type("State", (), {"viewport": Viewport(), "view": "map"})()
        _pan_with_arrow(window, state, curses.KEY_RIGHT)
        self.assertEqual((state.viewport.pan_x, state.viewport.pan_y), (10, 0))
        _pan_with_arrow(window, state, curses.KEY_DOWN)
        self.assertEqual((state.viewport.pan_x, state.viewport.pan_y), (10, 3))

    def test_pan_is_clamped_to_the_terminal(self) -> None:
        view = Viewport()
        for _ in range(50):
            view = view.pan(40, 40, 80, 24)
        self.assertEqual((view.pan_x, view.pan_y), (80, 24))


class DragTests(unittest.TestCase):
    def setUp(self) -> None:
        self.window = SizedWindow()
        self.state = type("State", (), {"viewport": Viewport(), "drag_origin": None,
                                        "drag_distance": 0})()

    def test_press_drag_release_pans(self) -> None:
        _drag(self.window, self.state, MouseEvent("press", 10, 20))
        self.assertEqual(self.state.drag_origin, (20, 10))
        _drag(self.window, self.state, MouseEvent("drag", 12, 25))
        self.assertEqual((self.state.viewport.pan_x, self.state.viewport.pan_y), (5, 2))
        _drag(self.window, self.state, MouseEvent("release", 12, 25))
        self.assertIsNone(self.state.drag_origin)
        self.assertEqual((self.state.viewport.pan_x, self.state.viewport.pan_y), (5, 2))

    def test_press_and_release_without_motion_still_pans(self) -> None:
        """Some terminals report only the two ends of a drag."""
        _drag(self.window, self.state, MouseEvent("press", 10, 20))
        _drag(self.window, self.state, MouseEvent("release", 4, 14))
        self.assertEqual((self.state.viewport.pan_x, self.state.viewport.pan_y), (-6, -6))

    def test_press_and_release_in_place_is_a_click(self) -> None:
        _drag(self.window, self.state, MouseEvent("press", 10, 20))
        clicked = _drag(self.window, self.state, MouseEvent("release", 10, 21))
        self.assertIsNotNone(clicked)
        self.assertEqual((self.state.viewport.pan_x, self.state.viewport.pan_y), (0, 0))

    def test_motion_without_a_press_is_ignored(self) -> None:
        _drag(self.window, self.state, MouseEvent("move", 3, 3))
        self.assertEqual((self.state.viewport.pan_x, self.state.viewport.pan_y), (0, 0))


class WheelTests(unittest.TestCase):
    def test_wheel_outside_the_map_zooms_around_the_centre(self) -> None:
        state = type("State", (), {"viewport": Viewport(), "view": "hosts"})()
        _zoom_with_wheel(state, None, MouseEvent("scroll", 5, 5, -1))
        self.assertGreater(state.viewport.zoom, 1.0)
        self.assertEqual((state.viewport.pan_x, state.viewport.pan_y), (0, 0))

    def test_wheel_over_the_map_anchors_on_the_pointer(self) -> None:
        layout = FrameLayout(tab_hits=(), map_region=(1, 0, 20, 60))
        state = type("State", (), {"viewport": Viewport(), "view": "map"})()
        pointer = MouseEvent("scroll", 12, 20, -1)  # panel-local (19, 10)
        before = state.viewport.unproject((19, 10), 60, 20)
        _zoom_with_wheel(state, layout, pointer)
        after = state.viewport.unproject((19, 10), 60, 20)
        self.assertLessEqual(abs(after[0] - before[0]), 1)
        self.assertLessEqual(abs(after[1] - before[1]), 1)
        self.assertGreater(state.viewport.zoom, 1.0)

    def test_wheel_down_zooms_out_again(self) -> None:
        state = type("State", (), {"viewport": Viewport(), "view": "map"})()
        layout = FrameLayout(tab_hits=(), map_region=(1, 0, 20, 60))
        _zoom_with_wheel(state, layout, MouseEvent("scroll", 5, 5, -1))
        zoomed = state.viewport.zoom
        _zoom_with_wheel(state, layout, MouseEvent("scroll", 5, 5, 1))
        self.assertLess(state.viewport.zoom, zoomed)


class DecodeTests(unittest.TestCase):
    def test_drag_phases_are_distinguished(self) -> None:
        import curses

        from lumos.tui.mouse import decode

        self.assertEqual(decode(curses.BUTTON1_PRESSED, 3, 4).kind, "press")
        self.assertEqual(
            decode(curses.BUTTON1_PRESSED | curses.REPORT_MOUSE_POSITION, 3, 4).kind, "drag"
        )
        self.assertEqual(decode(curses.BUTTON1_RELEASED, 3, 4).kind, "release")
        self.assertEqual(decode(curses.BUTTON1_CLICKED, 3, 4).kind, "click")


if __name__ == "__main__":
    unittest.main()
