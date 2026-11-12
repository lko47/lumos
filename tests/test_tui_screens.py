from __future__ import annotations

import unittest

from lumos.services.map_view import MapEdge, MapNode, MapSnapshot, ScanInfo
from lumos.tui import overlays, render
from lumos.tui.layout import Viewport
from lumos.tui.widgets import clip, display_width, safe_addstr


class RecordingWindow:
    """Minimal curses window that records text exactly as written."""

    def __init__(self, height: int = 30, width: int = 100) -> None:
        self.height = height
        self.width = width
        self.writes: list[str] = []
        self.refreshes = 0

    def getmaxyx(self) -> tuple[int, int]:
        return self.height, self.width

    def erase(self) -> None:
        self.writes.clear()

    def addnstr(self, _y: int, _x: int, text: str, width: int, _attr: int = 0) -> None:
        self.writes.append(text[: max(0, width)])

    def addch(self, _y: int, _x: int, char: str, _attr: int = 0) -> None:
        self.writes.append(char)

    def refresh(self) -> None:
        self.refreshes += 1

    def text(self) -> str:
        return "".join(self.writes)


def snapshot() -> MapSnapshot:
    root = MapNode("root", "root", "scanner-host", (), "", 0, 0, 0, ())
    host = MapNode("host", "device", "demo-host.example.invalid",
                   ("192.0.2.10",), "Example Linux 6.x", 2, 1, 1,
                   ("22/tcp", "443/tcp"))
    hop = MapNode("hop", "unknown_hop", "unresponsive hop", ("192.0.2.1",), "", 0, 0, 2, ())
    edges = (
        MapEdge("e1", "root", "hop", "traceroute", "nmap_xml", "scan-1", 0.9, "2026-11-08T16:00:00+00:00", "", "tester"),
        MapEdge("e2", "root", "host", "inferred", "nmap_xml", "scan-1", 0.4, "2026-11-08T16:00:01+00:00", "", "tester"),
    )
    scans = (
        ScanInfo("abcdef1234567890", "completed", ("192.0.2.10",), "2026-11-08T16:00:00+00:00",
                 "2026-11-08T16:00:05+00:00", 0, "tester", "eth0", "7.99", 1),
        ScanInfo("fedcba0987654321", "running", ("192.0.2.0/24",), "2026-11-08T16:05:00+00:00",
                 "", None, "tester", "eth0", "7.99", 3),
    )
    return MapSnapshot("engagement", "terminal smoke", 2, 1, 1, (root, host, hop), edges, scans,
                       "scanner-host", ("eth0 192.0.2.5",))


STYLES = {name: 0 for name in (
    "brand", "subtitle", "accent", "muted", "title", "border", "border_focus", "selected",
    "tab", "tab_active", "root", "device", "hop", "unknown_hop", "manual", "zone",
    "edge_traceroute", "edge_alternate", "edge_inferred", "edge_manual", "edge_imported",
    "scan_running", "scan_completed", "scan_failed", "scan_cancelled", "scan_queued",
    "meter_0", "meter_1", "meter_2", "meter_3", "meter_4", "help_key", "help_text",
    "palette_selected", "port_open", "ok", "warn", "error", "value", "label",
)}


class WidgetTests(unittest.TestCase):
    def test_display_width_counts_wide_glyphs(self) -> None:
        self.assertEqual(display_width("abc"), 3)
        self.assertEqual(display_width("良"), 2)

    def test_clip_adds_an_ellipsis_and_stays_ascii_safe(self) -> None:
        self.assertEqual(clip("abcdef", 3), "ab…")
        self.assertEqual(clip("abcdef", 3, unicode_ok=False), "ab~")
        self.assertEqual(clip("abc", 3), "abc")
        self.assertEqual(clip("abc", 0), "")

    def test_safe_addstr_ignores_negative_coordinates(self) -> None:
        window = RecordingWindow()
        safe_addstr(window, -1, 0, "ignored", 10)
        safe_addstr(window, 0, -1, "ignored", 10)
        safe_addstr(window, 0, 0, "kept", 0)
        self.assertEqual(window.text(), "")


class ScreenTests(unittest.TestCase):
    def setUp(self) -> None:
        self.snap = snapshot()

    def draw(self, state: render.ViewState, unicode_ok: bool = True, size=(30, 100)) -> str:
        window = RecordingWindow(*size)
        window.erase()
        render.draw_header(window, self.snap, state, STYLES, unicode_ok, "aurora", "256")
        if state.view == "hosts":
            render.draw_hosts_screen(window, self.snap, state, STYLES, unicode_ok)
        elif state.view == "scans":
            render.draw_scans_screen(window, self.snap, state, STYLES, unicode_ok)
        else:
            render.draw_map_screen(window, self.snap, state, STYLES, unicode_ok)
        render.draw_footer(window, self.snap, state, STYLES, unicode_ok, 0.0)
        return window.text()

    def test_header_shows_engagement_and_counters(self) -> None:
        text = self.draw(render.ViewState())
        self.assertIn("LUMOS", text)
        self.assertIn("terminal smoke", text)
        self.assertIn("scans 2", text)
        self.assertIn("active 1", text)
        self.assertIn("nodes 3", text)
        self.assertIn("MAP", text)
        self.assertIn("HOSTS", text)
        self.assertIn("SCANS", text)

    def test_map_screen_draws_sidebar_details_and_ports(self) -> None:
        state = render.ViewState(selected=1, selected_kind="node")
        text = self.draw(state)
        self.assertIn("TOPOLOGY", text)
        self.assertIn("3 nodes", text)
        self.assertIn("2 links", text)
        self.assertIn("demo-host.example.invalid", text)
        self.assertIn("22/tcp", text)
        self.assertIn("OPEN PORTS", text)
        self.assertIn("zoom 1.00x", text)

    def test_scanner_root_sidebar_lists_interfaces(self) -> None:
        text = self.draw(render.ViewState(selected=0))
        self.assertIn("SCANNER ROOT", text)
        self.assertIn("eth0 192.0.2.5", text)

    def test_edge_selection_shows_provenance(self) -> None:
        state = render.ViewState(selected=0, selected_kind="edge")
        text = self.draw(state)
        self.assertIn("EDGE", text)
        self.assertIn("CONFIDENCE", text)
        self.assertIn("0.90", text)
        self.assertIn("nmap_xml", text)
        self.assertIn("tester", text)

    def test_hosts_screen_lists_every_node(self) -> None:
        state = render.ViewState(view="hosts", selected=1)
        text = self.draw(state)
        self.assertIn("KIND", text)
        self.assertIn("PORTS", text)
        self.assertIn("REVIEW", text)
        self.assertIn("demo-host.example.invalid", text)
        self.assertIn("192.0.2.10", text)

    def test_scans_screen_shows_status_rows_and_detail(self) -> None:
        state = render.ViewState(view="scans", scan_selected=1)
        text = self.draw(state)
        self.assertIn("SCANS", text)
        self.assertIn("abcdef12", text)
        self.assertIn("completed", text)
        self.assertIn("running", text)
        self.assertIn("eth0", text)

    def test_ascii_mode_output_is_pure_ascii(self) -> None:
        for view, selected_kind in (("map", "node"), ("map", "edge"), ("hosts", "node"), ("scans", "node")):
            with self.subTest(view=view, kind=selected_kind):
                text = self.draw(render.ViewState(view=view, selected_kind=selected_kind), unicode_ok=False)
                self.assertTrue(text.isascii(), f"non-ASCII output in {view}")

    def test_small_terminal_reports_minimum_size(self) -> None:
        text = self.draw(render.ViewState(), size=(6, 30))
        self.assertIn("Terminal too small", text)

    def test_footer_shows_notification_and_hints(self) -> None:
        state = render.ViewState()
        state.notify("snapshot reloaded")
        state.message_until = float("inf")
        text = self.draw(state)
        self.assertIn("snapshot reloaded", text)
        self.assertIn("quit", text)


class OverlayTests(unittest.TestCase):
    def test_help_overlay_fits_the_screen_and_lists_keys(self) -> None:
        for height, width in ((24, 80), (18, 44), (14, 40)):
            with self.subTest(size=(height, width)):
                window = RecordingWindow(height, width)
                overlays.draw_help(window, STYLES, True)
                text = window.text()
                self.assertIn("HELP", text)
                self.assertIn("quit", text)
                self.assertLessEqual(len(window.writes), 4000)

    def test_palette_lists_entries_and_the_query(self) -> None:
        window = RecordingWindow(24, 80)
        entries = [("map", "show the topology map", None), ("scans", "scan history", None)]
        overlays.draw_palette(window, STYLES, True, "sc", entries, 1)
        text = window.text()
        self.assertIn("COMMAND PALETTE", text)
        self.assertIn("scan history", text)
        self.assertIn("sc", text)

    def test_palette_without_matches_says_so(self) -> None:
        window = RecordingWindow(24, 80)
        overlays.draw_palette(window, STYLES, True, "zzz", [], 0)
        self.assertIn("No matching command", window.text())

    def test_overlays_are_ascii_safe(self) -> None:
        window = RecordingWindow(24, 80)
        overlays.draw_help(window, STYLES, False)
        overlays.draw_palette(window, STYLES, False, "q", [], 0)
        self.assertTrue(window.text().isascii())


if __name__ == "__main__":
    unittest.main()
