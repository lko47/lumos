"""PTY-driven checks that the writable flows really work on a terminal."""

from __future__ import annotations

import fcntl
import os
import pty
import re
import select
import signal
import struct
import sys
import tempfile
import termios
import time
import unittest
from pathlib import Path

from lumos.core.database import initialize_database
from lumos.core.scope_store import add_scope_rule

ROOT = Path(__file__).resolve().parents[1]
FAKE_DIR = ROOT / "tests" / "fake_nmap"
FIXTURE = ROOT / "tests" / "fixtures" / "nmap" / "normal.xml"

_ANSI = re.compile(rb"\x1b\[[0-9;?]*[A-Za-z]|\x1b\([AB0]|\x1b[=>]|\r")


def _plain(buffer: bytearray) -> bytes:
    return _ANSI.sub(b"", bytes(buffer))


class PtySession:
    """One child `lumos` process attached to a pseudo-terminal."""

    def __init__(self, arguments: list[str], *, cwd: Path, state_home: Path, height: int = 30, width: int = 100) -> None:
        self.output = bytearray()
        self.pid, self.master = pty.fork()
        if self.pid == 0:  # pragma: no cover - child process
            env = os.environ.copy()
            env.update(
                {
                    "TERM": "xterm-256color",
                    "NO_COLOR": "1",
                    "LUMOS_ASCII": "1",
                    "LC_ALL": "C.UTF-8",
                    "XDG_STATE_HOME": str(state_home),
                    "NMAP_FAKE_FIXTURE": str(FIXTURE),
                    "PATH": str(FAKE_DIR) + os.pathsep + env.get("PATH", ""),
                    "PYTHONPATH": str(ROOT / "src") + os.pathsep + env.get("PYTHONPATH", ""),
                }
            )
            os.chdir(cwd)
            os.execve(sys.executable, [sys.executable, "-m", "lumos", *arguments], env)
            os._exit(127)
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", height, width, 0, 0))

    def read_until(self, needle: bytes, timeout: float = 12.0) -> bool:
        if needle in _plain(self.output):
            return True
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            ready, _, _ = select.select([self.master], [], [], 0.2)
            if not ready:
                continue
            try:
                chunk = os.read(self.master, 8192)
            except OSError:
                return False
            if not chunk:
                return False
            self.output.extend(chunk)
            if needle in _plain(self.output):
                return True
        return False

    def send(self, keys: bytes) -> None:
        os.write(self.master, keys)

    def wait(self, timeout: float = 8.0) -> int | None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            waited, status = os.waitpid(self.pid, os.WNOHANG)
            if waited:
                self.pid = -1
                return os.waitstatus_to_exitcode(status)
            time.sleep(0.05)
        return None

    def close(self) -> None:
        if self.pid > 0:
            try:
                os.kill(self.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                os.waitpid(self.pid, 0)
            except ChildProcessError:
                pass
            self.pid = -1
        try:
            os.close(self.master)
        except OSError:
            pass


class TuiFlowTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.state_home = self.dir / "state"
        self.session: PtySession | None = None

    def tearDown(self) -> None:
        if self.session is not None:
            self.session.close()

    def launch(self, *arguments: str) -> PtySession:
        self.session = PtySession(list(arguments), cwd=self.dir, state_home=self.state_home)
        return self.session

    def make_database(self, *, scope: bool = True) -> Path:
        db = self.dir / "engagement.sqlite"
        initialize_database(db, "flow test")
        if scope:
            add_scope_rule(db, "lab", "192.0.2.0/24", included=True, author="test")
        return db

    def test_start_screen_renders_and_quits(self) -> None:
        session = self.launch()
        self.assertTrue(session.read_until(b"Recent engagements"), _plain(session.output)[-800:])
        self.assertTrue(session.read_until(b"none yet"))
        session.send(b"q")
        self.assertEqual(session.wait(), 0)

    def test_new_engagement_flow_creates_a_database_and_opens_it(self) -> None:
        session = self.launch()
        self.assertTrue(session.read_until(b"Recent engagements"))
        session.send(b"n")
        self.assertTrue(session.read_until(b"new engagement"), _plain(session.output)[-800:])
        session.send(b"lab")
        session.send(b"\r")
        self.assertTrue(session.read_until(b"created engagement.sqlite"), _plain(session.output)[-1200:])
        session.send(b" ")
        self.assertTrue(session.read_until(b"LUMOS  MAP"), _plain(session.output)[-1200:])
        self.assertTrue((self.dir / "engagement.sqlite").is_file())
        session.send(b"q")
        self.assertTrue(session.read_until(b"Recent engagements"))
        session.send(b"q")
        self.assertEqual(session.wait(), 0)

    def test_scope_form_adds_a_rule_and_the_footer_counts_it(self) -> None:
        db = self.make_database(scope=False)
        session = self.launch(str(db))
        self.assertTrue(session.read_until(b"LUMOS  MAP"))
        session.send(b"P")
        self.assertTrue(session.read_until(b"no scope rules yet"), _plain(session.output)[-900:])
        session.send(b"a")
        self.assertTrue(session.read_until(b"add scope rule"), _plain(session.output)[-900:])
        session.send(b"192.0.2.0/24")
        session.send(b"\r")
        self.assertTrue(session.read_until(b"IN  cidr"), _plain(session.output)[-1200:])
        session.send(b"\x1b")
        session.send(b"q")
        self.assertEqual(session.wait(), 0)

    def test_scan_flow_runs_the_fake_nmap_and_reports_completion(self) -> None:
        db = self.make_database()
        session = self.launch(str(db))
        self.assertTrue(session.read_until(b"LUMOS  MAP"))
        session.send(b"S")
        self.assertTrue(session.read_until(b"targets"), _plain(session.output)[-900:])
        session.send(b"\r")
        self.assertTrue(
            session.read_until(b"scan completed", timeout=20.0),
            _plain(session.output)[-2000:],
        )
        session.send(b"q")
        self.assertEqual(session.wait(), 0)

    def test_scan_without_targets_is_refused_in_the_form(self) -> None:
        db = self.make_database(scope=False)
        session = self.launch(str(db))
        self.assertTrue(session.read_until(b"LUMOS  MAP"))
        session.send(b"S")
        self.assertTrue(session.read_until(b"targets"))
        session.send(b"\r")
        self.assertTrue(session.read_until(b"at least one target"), _plain(session.output)[-900:])
        session.send(b"\x1b")
        session.send(b"q")
        self.assertEqual(session.wait(), 0)

    def test_tools_check_and_activity_log_open_and_close(self) -> None:
        db = self.make_database()
        session = self.launch(str(db))
        self.assertTrue(session.read_until(b"LUMOS  MAP"))
        session.send(b"T")
        self.assertTrue(session.read_until(b"check database"), _plain(session.output)[-900:])
        session.send(b"\r")
        self.assertTrue(session.read_until(b"schema 3"), _plain(session.output)[-1200:])
        session.send(b" ")
        session.send(b"!")
        self.assertTrue(session.read_until(b"activity log"), _plain(session.output)[-900:])
        session.send(b"\x1b")
        session.send(b"q")
        self.assertEqual(session.wait(), 0)
