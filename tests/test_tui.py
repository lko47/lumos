from __future__ import annotations

import fcntl
import io
import os
import pty
import select
import signal
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from lumos.core.database import initialize_database
from lumos.core.scanning import scan_database
from lumos.core.scope_store import add_scope_rule
from lumos.services.map_view import MapEdge, MapNode, MapSnapshot, load_map_snapshot
from lumos.tui.app import _draw_map, run_tui

ROOT = Path(__file__).resolve().parents[1]
FAKE = ROOT / "tests" / "fake_nmap" / "nmap"
FIXTURE = ROOT / "tests" / "fixtures" / "nmap" / "normal.xml"


class RecordingWindow:
    def __init__(self, height: int = 14, width: int = 80) -> None:
        self.height = height
        self.width = width
        self.writes: list[str] = []

    def getmaxyx(self) -> tuple[int, int]:
        return self.height, self.width

    def erase(self) -> None:
        self.writes.clear()

    def addnstr(self, _y: int, _x: int, text: str, _width: int, _attr: int = 0) -> None:
        self.writes.append(text)

    def addch(self, _y: int, _x: int, char: str, _attr: int = 0) -> None:
        self.writes.append(char)

    def refresh(self) -> None:
        pass


class TuiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "engagement.sqlite"
        initialize_database(self.db, "terminal smoke")

    def test_map_uses_braille_for_unicode_and_keeps_ascii_fallback(self) -> None:
        root = MapNode("root", "root", "Scanner", (), "", 0, 0, 0)
        host = MapNode("host", "device", "Host", ("192.0.2.10",), "", 2, 0, 1)
        edge = MapEdge("edge", "root", "host", "traceroute", "nmap_xml", "scan", 1.0, "now", "now", "tester")
        snapshot = MapSnapshot("engagement", "test", 1, 0, 0, (root, host), (edge,))
        colors = {name: 0 for name in ("header", "plain", "selected", "edge", "review", "device", "hop", "manual")}

        unicode_window = RecordingWindow()
        _draw_map(unicode_window, snapshot, 1, "node", True, colors)
        unicode_text = "".join(unicode_window.writes)
        self.assertTrue(any(0x2800 <= ord(char) <= 0x28FF for char in unicode_text))

        ascii_window = RecordingWindow()
        _draw_map(ascii_window, snapshot, 1, "node", False, colors)
        ascii_text = "".join(ascii_window.writes)
        self.assertTrue(ascii_text.isascii())

    def test_redirected_tui_uses_plain_text_fallback(self) -> None:
        output = io.StringIO()
        with patch("sys.stdin", io.StringIO("")), patch("sys.stdout", output):
            result = run_tui(self.db)
        self.assertEqual(result, 0)
        self.assertIn("Lumos - terminal smoke", output.getvalue())
        self.assertIn("Scanner not yet recorded", output.getvalue())
        self.assertTrue(output.getvalue().isascii())

    def test_redirected_cli_uses_plain_text_fallback(self) -> None:
        env = os.environ.copy()
        env["PYTHONPATH"] = str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", "")
        result = subprocess.run(
            [sys.executable, "-m", "lumos", "tui", str(self.db)],
            env=env,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Lumos - terminal smoke", result.stdout)
        self.assertTrue(result.stdout.isascii())

    @unittest.skipUnless(os.name == "posix" and hasattr(pty, "fork"), "requires POSIX pseudo-terminals")
    def test_pty_receives_live_scan_updates_without_blocking_navigation(self) -> None:
        add_scope_rule(self.db, "lab", "192.0.2.0/24", included=True, author="test")
        host_xml = "".join(
            f'<host><status state="up" reason="syn-ack" reason_ttl="64"/>'
            f'<address addr="192.0.2.{index}" addrtype="ipv4"/>'
            f'<hostnames><hostname name="node-{index}.example.invalid" type="user"/></hostnames></host>'
            for index in range(1, 52)
        )
        fixture = Path(self.tmp.name) / "live.xml"
        fixture.write_text(
            '<?xml version="1.0"?><nmaprun scanner="nmap" args="synthetic" version="7.99">'
            + host_xml
            + '<runstats><finished exit="success"/><hosts up="51" down="0" total="51"/></runstats></nmaprun>',
            encoding="utf-8",
        )
        pid, master = pty.fork()
        if pid == 0:  # pragma: no cover - child process
            env = os.environ.copy()
            env.update({
                "TERM": "xterm-256color",
                "NO_COLOR": "1",
                "LUMOS_ASCII": "1",
                "LC_ALL": "C.UTF-8",
                "PYTHONPATH": str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", ""),
            })
            os.execve(sys.executable, [sys.executable, "-m", "lumos", "tui", str(self.db)], env)
            os._exit(127)

        output = bytearray()
        exit_code = None
        scan_thread = None
        scan_errors: list[BaseException] = []
        try:
            fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 28, 100, 0, 0))

            def read_until(needle: bytes, timeout: float = 6.0) -> bool:
                if needle in output:
                    return True
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    ready, _, _ = select.select([master], [], [], 0.2)
                    if not ready:
                        continue
                    try:
                        chunk = os.read(master, 8192)
                    except OSError:
                        return False
                    if not chunk:
                        return False
                    output.extend(chunk)
                    if needle in output:
                        return True
                return False

            self.assertTrue(read_until(b"nodes 1"), "initial empty map did not render")

            def run_scan() -> None:
                try:
                    with patch.dict(os.environ, {
                        "NMAP_FAKE_FIXTURE": str(fixture),
                        "NMAP_FAKE_CHUNK_SIZE": "4096",
                        "NMAP_FAKE_HOLD_AFTER_OUTPUT": "3",
                    }):
                        scan_database(self.db, "lab", ["192.0.2.10"], executable=str(FAKE), operator="test")
                except BaseException as exc:
                    scan_errors.append(exc)

            scan_thread = threading.Thread(target=run_scan, name="test-live-scan")
            scan_thread.start()
            deadline = time.monotonic() + 6.0
            live_snapshot = None
            while time.monotonic() < deadline:
                candidate = load_map_snapshot(self.db)
                if candidate.active_scans == 1 and len(candidate.nodes) == 51:
                    live_snapshot = candidate
                    break
                time.sleep(0.05)
            self.assertIsNotNone(live_snapshot, "fake scan did not commit a 50-host batch while remaining active")
            self.assertTrue(scan_thread.is_alive(), "fake scan finished before the live map update was observed")
            time.sleep(1.1)  # allow the TUI's data_version watcher to publish the committed snapshot
            fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 28, 101, 0, 0))
            self.assertTrue(read_until(b"active 1"), f"TUI did not redraw active scan status: {bytes(output[-3000:])!r}")
            self.assertTrue(read_until(b"nodes 51"), f"TUI did not display the committed host batch: {bytes(output[-3000:])!r}")
            os.write(master, b"v")
            self.assertTrue(read_until(b"HOSTS  |  terminal smoke"), "navigation was blocked while the scan was running")
            os.write(master, b"q")
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                waited, status = os.waitpid(pid, os.WNOHANG)
                if waited:
                    exit_code = os.waitstatus_to_exitcode(status)
                    pid = -1
                    break
                time.sleep(0.05)
            self.assertIsNotNone(exit_code, "TUI did not quit during the scan")
            self.assertEqual(exit_code, 0)
            scan_thread.join(timeout=8.0)
            self.assertFalse(scan_thread.is_alive(), "fake scan thread did not finish")
            self.assertFalse(scan_errors, f"fake scan failed: {scan_errors!r}")
        finally:
            if scan_thread and scan_thread.is_alive():
                scan_thread.join(timeout=8.0)
            if pid > 0:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
            os.close(master)

    @unittest.skipUnless(os.name == "posix" and hasattr(pty, "fork"), "requires POSIX pseudo-terminals")
    def test_pty_unicode_map_emits_braille_cells(self) -> None:
        add_scope_rule(self.db, "lab", "192.0.2.0/24", included=True, author="test")
        with patch.dict(os.environ, {"NMAP_FAKE_FIXTURE": str(FIXTURE)}):
            scan_database(self.db, "lab", ["192.0.2.10"], executable=str(FAKE), operator="test")
        pid, master = pty.fork()
        if pid == 0:  # pragma: no cover - child process
            env = os.environ.copy()
            env.update({
                "TERM": "xterm-256color",
                "NO_COLOR": "1",
                "LC_ALL": "C.UTF-8",
                "PYTHONPATH": str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", ""),
            })
            env.pop("LUMOS_ASCII", None)
            os.execve(sys.executable, [sys.executable, "-m", "lumos", "tui", str(self.db)], env)
            os._exit(127)

        output = bytearray()
        exit_code = None
        try:
            fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 28, 100, 0, 0))
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline and b"\xe2\xa0" not in output:
                ready, _, _ = select.select([master], [], [], 0.2)
                if ready:
                    try:
                        output.extend(os.read(master, 8192))
                    except OSError:
                        break
            self.assertIn(b"\xe2\xa0", output, f"no braille cells in curses output: {bytes(output[-1000:])!r}")
            os.write(master, b"q")
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                waited, status = os.waitpid(pid, os.WNOHANG)
                if waited:
                    exit_code = os.waitstatus_to_exitcode(status)
                    pid = -1
                    break
                time.sleep(0.05)
            self.assertEqual(exit_code, 0)
        finally:
            if pid > 0:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
            os.close(master)

    @unittest.skipUnless(os.name == "posix" and hasattr(pty, "fork"), "requires POSIX pseudo-terminals")
    def test_pty_launch_navigation_and_clean_quit(self) -> None:
        add_scope_rule(self.db, "lab", "192.0.2.0/24", included=True, author="test")
        with patch.dict(os.environ, {"NMAP_FAKE_FIXTURE": str(FIXTURE)}):
            scan_database(self.db, "lab", ["192.0.2.10"], executable=str(FAKE), operator="test")
        pid, master = pty.fork()
        if pid == 0:  # pragma: no cover - child process
            env = os.environ.copy()
            env.update({
                "TERM": "xterm-256color",
                "NO_COLOR": "1",
                "LUMOS_ASCII": "1",
                "LC_ALL": "C.UTF-8",
                "PYTHONPATH": str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", ""),
            })
            os.execve(sys.executable, [sys.executable, "-m", "lumos", "tui", str(self.db)], env)
            os._exit(127)

        output = bytearray()
        exit_code = None
        try:
            fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 28, 100, 0, 0))

            def read_until(needle: bytes, timeout: float = 5.0) -> bool:
                if needle in output:
                    return True
                deadline = time.monotonic() + timeout
                while time.monotonic() < deadline:
                    ready, _, _ = select.select([master], [], [], 0.2)
                    if not ready:
                        continue
                    try:
                        chunk = os.read(master, 8192)
                    except OSError:
                        return False
                    if not chunk:
                        return False
                    output.extend(chunk)
                    if needle in output:
                        return True
                return False

            self.assertTrue(read_until(b"LUMOS  MAP"), "initial map view did not render")
            os.write(master, b"e")
            self.assertTrue(read_until(b"EDGE DETAILS"), "e key did not select edge provenance details")
            self.assertTrue(read_until(b"Confidence:"), f"edge confidence was not rendered; bytes={bytes(output[-1500:])!r}")
            os.write(master, b"v")
            self.assertTrue(read_until(b"HOSTS  |  terminal smoke"), f"v key did not open host list; terminal bytes: {bytes(output[-2000:])!r}")
            os.write(master, b"q")
            deadline = time.monotonic() + 5.0
            while time.monotonic() < deadline:
                waited, status = os.waitpid(pid, os.WNOHANG)
                if waited:
                    exit_code = os.waitstatus_to_exitcode(status)
                    pid = -1
                    break
                time.sleep(0.05)
            self.assertIsNotNone(exit_code, "TUI did not quit after q")
            self.assertEqual(exit_code, 0)
        finally:
            if pid > 0:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                try:
                    os.waitpid(pid, 0)
                except ChildProcessError:
                    pass
            os.close(master)


if __name__ == "__main__":
    unittest.main()
