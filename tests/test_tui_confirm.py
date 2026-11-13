"""Out-of-scope confirmation: prime a checkbox, then press the red button."""

from __future__ import annotations

import unittest
from unittest import mock

from lumos.tui import forms, mouse, widgets


class GridWindow:
    """A curses window double that keeps characters and attributes."""

    def __init__(self, height: int = 24, width: int = 90) -> None:
        self.height = height
        self.width = width
        self.cells: dict[tuple[int, int], tuple[str, int]] = {}
        self.attrs: dict[tuple[int, int], int] = {}
        self.keys: list[int] = []
        self.frames: list[dict[tuple[int, int], tuple[str, int]]] = []

    # curses surface -------------------------------------------------------
    def getmaxyx(self) -> tuple[int, int]:
        return self.height, self.width

    def addnstr(self, y: int, x: int, text: str, width: int, attr: int = 0) -> None:
        if y < 0 or y >= self.height or x < 0 or x >= self.width:
            return
        for offset, char in enumerate(text[:width]):
            if x + offset >= self.width:
                break
            self.cells[(y, x + offset)] = (char, attr)

    def chgat(self, y: int, x: int, num: int, attr: int) -> None:
        for offset in range(num):
            self.attrs[(y, x + offset)] = attr

    def refresh(self) -> None:
        self.frames.append(dict(self.cells))

    def timeout(self, value: int) -> None:
        pass

    def keypad(self, flag: bool) -> None:
        pass

    def getch(self) -> int:
        return self.keys.pop(0) if self.keys else 27

    # helpers --------------------------------------------------------------
    def text(self) -> str:
        rows: dict[int, list[str]] = {}
        for (y, x), (char, _attr) in self.cells.items():
            rows.setdefault(y, [])
            while len(rows[y]) <= x:
                rows[y].append(" ")
            rows[y][x] = char
        return "\n".join("".join(rows[y]).rstrip() for y in sorted(rows))


def _run(window: GridWindow, keys: list[int]) -> bool:
    window.keys = list(keys)
    return forms.confirm_scope(
        window,
        {},
        True,
        title="out of scope",
        lines=["192.0.2.10 is not covered by an included scope rule."],
        checkbox_label="I understand and want to scan outside the scope",
    )


class CheckboxConfirmationTests(unittest.TestCase):
    def setUp(self) -> None:
        mouse.clear()

    def test_escape_cancels_and_nothing_is_armed(self) -> None:
        window = GridWindow()
        self.assertFalse(_run(window, [27]))
        self.assertIn("[ ]", window.text())

    def test_enter_without_priming_does_not_confirm(self) -> None:
        window = GridWindow()
        self.assertFalse(_run(window, [10, 27]))
        self.assertIn("prime the checkbox first", window.text())

    def test_space_primes_then_enter_confirms(self) -> None:
        window = GridWindow()
        self.assertTrue(_run(window, [ord(" "), 10]))
        frames = [frame for frame in window.frames]
        self.assertTrue(any("[x]" in _frame_text(frame) for frame in frames))

    def test_primed_button_is_filled_red(self) -> None:
        import curses

        window = GridWindow()
        _run(window, [ord(" "), 27])
        reversed_cells = [
            (y, x, char)
            for (y, x), (char, attr) in window.cells.items()
            if attr & curses.A_REVERSE
        ]
        self.assertTrue(reversed_cells, "primed button was not filled")
        self.assertTrue(any(char.strip() for _y, _x, char in reversed_cells))

    def test_mouse_primes_the_checkbox_then_confirms(self) -> None:
        window = GridWindow()
        window.keys = [-99, -99]
        kinds = iter(["checkbox", "button"])
        with mock.patch.object(forms.mouse, "is_mouse", lambda key: key == -99), \
                mock.patch.object(forms.mouse, "read_action", lambda _w: (None, {"kind": next(kinds)})):
            self.assertTrue(
                forms.confirm_scope(
                    window, {}, True,
                    title="out of scope",
                    lines=["192.0.2.10 is outside scope."],
                    checkbox_label="I understand",
                )
            )

    def test_clicking_the_button_before_priming_warns(self) -> None:
        window = GridWindow()
        window.keys = [-99, -99]
        kinds = iter(["button", "cancel"])
        with mock.patch.object(forms.mouse, "is_mouse", lambda key: key == -99), \
                mock.patch.object(forms.mouse, "read_action", lambda _w: (None, {"kind": next(kinds)})):
            # "cancel" is not handled, so the next getch (default Esc) ends it
            self.assertFalse(
                forms.confirm_scope(
                    window, {}, True,
                    title="out of scope",
                    lines=["192.0.2.10 is outside scope."],
                    checkbox_label="I understand",
                )
            )
        self.assertIn("prime the checkbox first", window.text())


class DialogOpacityTests(unittest.TestCase):
    def setUp(self) -> None:
        mouse.clear()

    def test_map_text_is_blanked_in_the_ring_around_a_dialog(self) -> None:
        window = GridWindow(24, 90)
        for y in range(24):
            for x in range(90):
                window.cells[(y, x)] = ("X", 0)
        widgets.set_backdrop(window, lambda: None)
        self.addCleanup(widgets.set_backdrop, window, None)
        forms._draw(window, {}, True, title="scan", fields=[forms.Field("t", "t")],
                    active=0, note="", error="")
        box = next(
            spot for spot in mouse.spots() if spot.action["kind"] == "field"
        )
        top, left = box.top - 2, box.left - 2
        self.assertEqual(window.cells[(top, left)][0], " ")
        self.assertEqual(window.cells[(top, left + 1)][0], " ")

    def test_dim_region_reattributes_text(self) -> None:
        import curses

        window = GridWindow(6, 20)
        window.cells[(1, 1)] = ("Z", 0)
        widgets.dim_region(window, (0, 0, 6, 20), curses.A_DIM)
        self.assertEqual(window.attrs[(1, 1)], curses.A_DIM)


def _frame_text(frame: dict[tuple[int, int], tuple[str, int]]) -> str:
    return "".join(char for char, _attr in frame.values())


if __name__ == "__main__":
    unittest.main()