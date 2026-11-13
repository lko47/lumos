"""Modal layout, resize clamping and stale-scan reconciliation."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lumos.core.database import initialize_database
from lumos.core.nmap.runner import _supports_stats, build_nmap_argv
from lumos.core.nmap.xml_stream import parse_nmap_xml
from lumos.core.scan_store import acquire_scan_lock, reconcile_interrupted_scans, release_scan_lock
from lumos.tui import forms
from lumos.tui.widgets import draw_box


class GridWindow:
    """A curses window that keeps a character grid so overlaps are visible."""

    def __init__(self, height: int = 20, width: int = 80) -> None:
        self.height = height
        self.width = width
        self.grid = [[" "] * width for _ in range(height)]
        self.writes: list[tuple[int, int, str]] = []

    def getmaxyx(self) -> tuple[int, int]:
        return self.height, self.width

    def erase(self) -> None:
        self.grid = [[" "] * self.width for _ in range(self.height)]
        self.writes.clear()

    def addnstr(self, y: int, x: int, text: str, width: int, _attr: int = 0) -> None:
        if y < 0 or y >= self.height or x < 0 or x >= self.width:
            raise AssertionError(f"write outside window at {y},{x}: {text!r}")
        if width < 0:
            raise AssertionError("negative width")
        self.writes.append((y, x, text))
        for offset, char in enumerate(text[:width]):
            column = x + offset
            if column >= self.width:
                raise AssertionError(f"write past right edge at {y},{column}: {text!r}")
            self.grid[y][column] = char

    def refresh(self) -> None:
        pass

    def timeout(self, _value: int) -> None:
        pass

    def getch(self) -> int:
        return -1

    def text(self) -> str:
        return "\n".join("".join(row).rstrip() for row in self.grid)


class DrawBoxClearingTests(unittest.TestCase):
    def test_draw_box_blanks_its_rectangle(self) -> None:
        window = GridWindow(12, 60)
        for row in range(window.height):
            for column in range(window.width):
                window.grid[row][column] = "X"
        draw_box(window, 2, 4, 6, 30, title=" scan ", unicode_ok=True)
        interior = window.grid[3][5:33]
        self.assertEqual("".join(interior).strip(), "", "interior was not cleared before drawing")


class FormLayoutTests(unittest.TestCase):
    def test_form_redraw_leaves_exactly_one_box(self) -> None:
        window = GridWindow(24, 80)
        fields = [forms.Field("targets", "targets", value="192.0.2.0/24")]
        forms._draw(window, {}, True, title="scan", fields=fields, active=0, note="", error="")
        forms._draw(
            window,
            {},
            True,
            title="scan",
            fields=fields,
            active=0,
            note="Type exactly: SCAN OUT OF SCOPE: 198.51.100.0/24",
            error="phrase does not match",
        )
        rendered = window.text()
        self.assertEqual(rendered.count("╭"), 1, rendered)
        self.assertEqual(rendered.count("╰"), 1, rendered)

    def test_long_phrase_is_wrapped_not_clipped(self) -> None:
        window = GridWindow(24, 46)
        phrase = "SCAN OUT OF SCOPE: 198.51.100.0/24, 203.0.113.7"
        forms._draw(
            window,
            {},
            True,
            title="out-of-scope targets",
            fields=[forms.Field("phrase", "phrase")],
            active=0,
            note=f"Type exactly: {phrase}",
            error="",
        )
        rendered = window.text()
        self.assertIn("198.51.100.0/24", rendered)
        self.assertIn("203.0.113.7", rendered)
        self.assertNotIn("…", rendered)

    def test_narrow_terminal_keeps_the_box_inside(self) -> None:
        window = GridWindow(14, 30)
        forms._draw(
            window,
            {},
            True,
            title="scan",
            fields=[forms.Field("targets", "targets", value="10.0.0.0/24")],
            active=0,
            note="Lumos runs the installed Nmap directly; targets stay scope-checked.",
            error="",
        )
        rendered = window.text()
        self.assertIn("scan", rendered)
        self.assertEqual(rendered.count("╭"), 1, rendered)

    def test_tiny_terminal_reports_itself_instead_of_drawing(self) -> None:
        window = GridWindow(6, 20)
        forms._draw(
            window,
            {},
            True,
            title="scan",
            fields=[forms.Field("targets", "targets")],
            active=0,
            note="",
            error="",
        )
        self.assertIn("terminal too small", window.text())
        self.assertEqual(window.text().count("╭"), 0)


class ScanProgressTests(unittest.TestCase):
    def test_stats_every_is_enabled_for_modern_nmap(self) -> None:
        self.assertTrue(_supports_stats("Nmap version 7.993 ( https://nmap.org )", ""))
        self.assertFalse(_supports_stats("Nmap version 7.40", ""))
        argv = build_nmap_argv("/usr/bin/nmap", ["127.0.0.1"], options=["-sT"], stats_every=True)
        self.assertIn("--stats-every", argv)
        self.assertEqual(argv[argv.index("--stats-every") + 1], "5s")


class TaskProgressTests(unittest.TestCase):
    def test_taskprogress_is_forwarded_as_progress(self) -> None:
        xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE nmaprun>\n'
            b'<nmaprun scanner="nmap" args="nmap">'
            b'<taskprogress task="service_scan" time="123" percent="40.00" '
            b'remaining="10" etc="999"/>'
            b"</nmaprun>"
        )
        notes: list[str] = []
        list(parse_nmap_xml([xml], on_progress=notes.append))
        self.assertTrue(notes, "no progress was reported")
        self.assertIn("service scan", notes[0].lower())
        self.assertIn("40%", notes[0])
        self.assertIn("10 left", notes[0])


class InterruptedScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "engagement.sqlite"
        initialize_database(self.db, "interrupted scans")
        conn = sqlite3.connect(self.db)
        with conn:
            engagement = conn.execute("SELECT id FROM engagement").fetchone()[0]
            conn.execute(
                "INSERT INTO vantage_points(id, engagement_id, scanner_name, created_at) "
                "VALUES ('vp-1', ?, 'test', datetime('now'))",
                (engagement,),
            )
            conn.execute(
                "INSERT INTO scans(id, engagement_id, vantage_point_id, exact_args_json, "
                "redacted_args_json, targets_json, started_at, status) "
                "VALUES ('scan-1', ?, 'vp-1', '[]', '[]', '[]', datetime('now'), 'running')",
                (engagement,),
            )
        conn.close()

    def _status(self) -> str:
        conn = sqlite3.connect(self.db)
        try:
            return str(conn.execute("SELECT status FROM scans WHERE id = 'scan-1'").fetchone()[0])
        finally:
            conn.close()

    def test_dead_running_scan_is_closed_and_logged(self) -> None:
        self.assertEqual(reconcile_interrupted_scans(self.db), 1)
        self.assertEqual(self._status(), "failed")
        conn = sqlite3.connect(self.db)
        try:
            events = [row[0] for row in conn.execute("SELECT event_type FROM audit_events")]
        finally:
            conn.close()
        self.assertIn("scan_interrupted", events)

    def test_live_scan_is_left_alone(self) -> None:
        handle = acquire_scan_lock(self.db)
        try:
            self.assertEqual(reconcile_interrupted_scans(self.db), 0)
            self.assertEqual(self._status(), "running")
        finally:
            release_scan_lock(handle)


if __name__ == "__main__":
    unittest.main()
