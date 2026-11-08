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
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from lumos.core.database import initialize_database
from lumos.core.scanning import scan_database
from lumos.core.scope_store import add_scope_rule
from lumos.tui.app import run_tui

ROOT = Path(__file__).resolve().parents[1]
FAKE = ROOT / "tests" / "fake_nmap" / "nmap"
FIXTURE = ROOT / "tests" / "fixtures" / "nmap" / "normal.xml"


class TuiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "engagement.sqlite"
        initialize_database(self.db, "terminal smoke")

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
            self.assertTrue(read_until(b"Confidence:"), "edge confidence was not rendered")
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
