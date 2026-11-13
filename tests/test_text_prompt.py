"""The text prompt: type, backspace, Enter, Esc - and nothing else."""

from __future__ import annotations

import curses
import unittest

from lumos.tui import forms


class GridWindow:
    """Curses double: records text and answers keys from a queue."""

    def __init__(self, keys: list[int], height: int = 24, width: int = 90) -> None:
        self.height = height
        self.width = width
        self.keys = list(keys)
        self.cells: dict[tuple[int, int], str] = {}

    def getmaxyx(self) -> tuple[int, int]:
        return self.height, self.width

    def addnstr(self, y: int, x: int, text: str, width: int, _attr: int = 0) -> None:
        for offset, char in enumerate(text[:width]):
            if 0 <= y < self.height and 0 <= x + offset < self.width:
                self.cells[(y, x + offset)] = char

    def chgat(self, *_args: int) -> None:
        pass

    def refresh(self) -> None:
        pass

    def timeout(self, _value: int) -> None:
        pass

    def clearok(self, _value: bool) -> None:
        pass

    def erase(self) -> None:
        self.cells.clear()

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


def keys_for(text: str) -> list[int]:
    return [ord(char) for char in text]


class TextPromptTests(unittest.TestCase):
    def test_typing_and_enter_returns_the_line(self) -> None:
        window = GridWindow(keys_for("jump host") + [10])
        self.assertEqual(forms.text_prompt(window, {}, True, "note"), "jump host")

    def test_escape_returns_none_and_discards_the_text(self) -> None:
        window = GridWindow(keys_for("discard me") + [27])
        self.assertIsNone(forms.text_prompt(window, {}, True, "note"))

    def test_backspace_edits_before_accepting(self) -> None:
        window = GridWindow(keys_for("abc") + [curses.KEY_BACKSPACE, ord("d"), 10])
        self.assertEqual(forms.text_prompt(window, {}, True, "note"), "abd")

    def test_an_empty_line_is_none(self) -> None:
        window = GridWindow([10])
        self.assertIsNone(forms.text_prompt(window, {}, True, "note"))

    def test_the_character_cap_is_enforced(self) -> None:
        window = GridWindow(keys_for("abcdefghij") + [10])
        result = forms.text_prompt(window, {}, True, "note", forms.PromptOptions(max_chars=4))
        self.assertEqual(result, "abcd")

    def test_the_note_and_counter_are_drawn(self) -> None:
        window = GridWindow(keys_for("x") + [10])
        forms.text_prompt(window, {}, True, "note", forms.PromptOptions(note="why this host matters"))
        drawn = window.text()
        self.assertIn("why this host matters", drawn)
        self.assertIn("Enter saves", drawn)

    def test_a_tiny_terminal_cancels_instead_of_crashing(self) -> None:
        window = GridWindow([], height=4, width=12)
        self.assertIsNone(forms.text_prompt(window, {}, True, "note"))


if __name__ == "__main__":
    unittest.main()
