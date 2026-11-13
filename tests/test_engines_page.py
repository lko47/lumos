"""The enumeration settings page: installed engines, as checkboxes."""

from __future__ import annotations

import curses
import unittest
from types import SimpleNamespace

from lumos.tui import forms, mouse


class GridWindow:
    """Curses window double that keeps characters and a key queue."""

    def __init__(self, height: int = 26, width: int = 96) -> None:
        self.height = height
        self.width = width
        self.cells: dict[tuple[int, int], str] = {}
        self.keys: list[int] = []

    def getmaxyx(self) -> tuple[int, int]:
        return self.height, self.width

    def addnstr(self, y: int, x: int, text: str, width: int, _attr: int = 0) -> None:
        if y < 0 or y >= self.height or x < 0 or x >= self.width:
            return
        for offset, char in enumerate(text[:width]):
            if x + offset >= self.width:
                break
            self.cells[(y, x + offset)] = char

    def chgat(self, y: int, x: int, num: int, _attr: int) -> None:
        pass

    def refresh(self) -> None:
        pass

    def timeout(self, _value: int) -> None:
        pass

    def getch(self) -> int:
        return self.keys.pop(0) if self.keys else 27

    def text(self) -> str:
        rows: dict[int, list[str]] = {}
        for (y, x), char in self.cells.items():
            rows.setdefault(y, [])
            while len(rows[y]) <= x:
                rows[y].append(" ")
            rows[y][x] = char
        return "\n".join("".join(rows[y]).rstrip() for y in sorted(rows))


def row(name: str, installed: bool = True, enabled: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        name=name,
        path=f"/usr/bin/{name}" if installed else None,
        installed=installed,
        enabled=enabled and installed,
    )


class SettingsPageTests(unittest.TestCase):
    def setUp(self) -> None:
        mouse.clear()

    def test_page_lists_every_engine_with_a_checkbox(self) -> None:
        window = GridWindow()
        rows = [row("nmap"), row("masscan", installed=False, enabled=False), row("rustscan")]
        forms.engine_settings(window, {}, True, rows, toggle=None)
        text = window.text()
        self.assertIn("Installed commands to enumerate with:", text)
        self.assertIn("[x] nmap", text)
        self.assertIn("[ ] masscan", text)
        self.assertIn("not installed", text)

    def test_space_toggles_the_highlighted_engine(self) -> None:
        window = GridWindow()
        rows = [row("nmap"), row("rustscan")]
        window.keys = [curses.KEY_DOWN, ord(" "), 27]
        seen: list[str] = []

        def toggle(name: str):
            seen.append(name)
            return [row("nmap"), row("rustscan", enabled=(name != "rustscan"))]

        forms.engine_settings(window, {}, True, rows, toggle=toggle)
        self.assertEqual(seen, ["rustscan"])

    def test_escape_closes_without_toggling(self) -> None:
        window = GridWindow()
        seen: list[str] = []
        forms.engine_settings(
            window, {}, True, [row("nmap")], toggle=lambda name: seen.append(name) or []
        )
        self.assertEqual(seen, [])

    def test_clicking_a_row_toggles_that_row(self) -> None:
        window = GridWindow()
        seen: list[str] = []
        forms.engine_settings(
            window, {}, True, [row("nmap"), row("masscan")],
            toggle=lambda name: seen.append(name) or [row("nmap"), row("masscan")],
        )
        self.assertEqual(seen, [])

    def test_a_narrow_terminal_refuses_the_page(self) -> None:
        window = GridWindow(height=5, width=12)
        forms.engine_settings(window, {}, True, [row("nmap")], toggle=None)
        self.assertIn("terminal too", window.text())


if __name__ == "__main__":
    unittest.main()