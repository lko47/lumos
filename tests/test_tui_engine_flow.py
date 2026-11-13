"""The TUI scan dialog offers the engines that are installed and switched on."""

from __future__ import annotations

import time
import unittest
from pathlib import Path
from unittest import mock

from lumos.core import engine_scan, engines
from lumos.tui import flows


class GridWindow:
    """Minimal curses double: records text, answers keys from a queue."""

    def __init__(self, height: int = 24, width: int = 90) -> None:
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
        return self.keys.pop(0) if self.keys else -1

    def text(self) -> str:
        rows: dict[int, list[str]] = {}
        for (y, x), char in self.cells.items():
            rows.setdefault(y, [])
            while len(rows[y]) <= x:
                rows[y].append(" ")
            rows[y][x] = char
        return "\n".join("".join(rows[y]).rstrip() for y in sorted(rows))


class EngineChoiceTests(unittest.TestCase):
    def test_only_installed_and_enabled_engines_are_offered(self) -> None:
        found = {"nmap": "/usr/bin/nmap", "masscan": "/usr/bin/masscan",
                 "naabu": None, "rustscan": None}
        with mock.patch.object(engines, "detect", return_value=found), \
                mock.patch.object(engines, "load_enabled",
                                  return_value=frozenset({"nmap", "masscan", "naabu"})):
            self.assertEqual(flows.engine_choices(), ("nmap", "masscan"))

    def test_nmap_leads_even_when_it_is_not_first_in_the_catalogue(self) -> None:
        found = {engine.name: "/usr/bin/" + engine.binary for engine in engines.ENGINES}
        with mock.patch.object(engines, "detect", return_value=found), \
                mock.patch.object(engines, "load_enabled",
                                  return_value=frozenset(name for name in found)):
            self.assertEqual(flows.engine_choices()[0], "nmap")

    def test_the_dialog_still_works_with_nothing_but_nmap(self) -> None:
        found = {"nmap": "/usr/bin/nmap", "masscan": None, "naabu": None, "rustscan": None}
        with mock.patch.object(engines, "detect", return_value=found), \
                mock.patch.object(engines, "load_enabled", return_value=frozenset({"nmap"})):
            self.assertEqual(flows.engine_choices(), ("nmap",))


class EngineFlowTests(unittest.TestCase):
    def test_successful_run_reports_hosts(self) -> None:
        window = GridWindow()
        request = flows.EngineRequest(
            engine="masscan", targets=("192.0.2.40", "192.0.2.41"), network="lab",
            operator="tester",
        )
        def slow_scan(*_args, **_kwargs):
            time.sleep(0.05)
            return ("id", 2, "")

        with mock.patch.object(engine_scan, "scan_with_engine", side_effect=slow_scan):
            result = flows._engine_scan_flow(window, {}, True, Path("db.sqlite"), request)
        self.assertTrue(result.ok)
        self.assertIn("4 host(s)", result.message, "one scan row per target, hosts summed")
        self.assertIn("masscan", window.text())

    def test_engine_failure_is_a_message_not_a_crash(self) -> None:
        window = GridWindow()
        request = flows.EngineRequest(
            engine="masscan", targets=("192.0.2.40",), network="lab", operator="tester",
        )
        with mock.patch.object(engine_scan, "scan_with_engine",
                               side_effect=engine_scan.EngineScanError("masscan is not installed")):
            result = flows._engine_scan_flow(window, {}, True, Path("db.sqlite"), request)
        self.assertFalse(result.ok)
        self.assertIn("not installed", result.message)

    def test_escape_leaves_the_scan_running(self) -> None:
        window = GridWindow()
        window.keys = [27]
        request = flows.EngineRequest(
            engine="naabu", targets=("192.0.2.40",), network="lab", operator="tester",
        )
        with mock.patch.object(engine_scan, "scan_with_engine", return_value=("id", 1, "")):
            result = flows._engine_scan_flow(window, {}, True, Path("db.sqlite"), request)
        self.assertTrue(result.ok)


if __name__ == "__main__":
    unittest.main()