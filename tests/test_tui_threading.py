"""Threading contract: slow work never runs on the curses (main) thread."""

from __future__ import annotations

import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from lumos.core.database import initialize_database, open_database
from lumos.core.scope_store import add_scope_rule
from lumos.services import actions
from lumos.services.map_view import MapSnapshotWatcher
from lumos.tui import flows


class IdleWindow:
    """Minimal curses window: nothing is drawn, getch never blocks."""

    def __init__(self) -> None:
        self.timeouts: list[int] = []

    def getmaxyx(self) -> tuple[int, int]:
        return 30, 100

    def addnstr(self, *_args, **_kwargs) -> None:
        pass

    def addch(self, *_args, **_kwargs) -> None:
        pass

    def refresh(self) -> None:
        pass

    def timeout(self, value: int) -> None:
        self.timeouts.append(value)

    def getch(self) -> int:
        return -1

    def clearok(self, _flag: bool) -> None:
        pass


class SlowWorkStaysOffTheUiThreadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "engagement.sqlite"
        initialize_database(self.db, "threading")

    def test_open_engagement_runs_on_a_worker_thread(self) -> None:
        seen: list[str] = []

        def fake_open(path):
            seen.append(threading.current_thread().name)
            time.sleep(0.05)
            return actions.ActionResult(True, "opened", payload={"path": str(path), "name": "x"})

        styles = {"accent": 0, "muted": 0, "plain": 0}
        with patch.object(flows.forms, "run_form", return_value={"path": str(self.db)}), patch.object(
            actions, "open_engagement", side_effect=fake_open
        ):
            opened = flows.flow_open_path(IdleWindow(), styles, True)

        self.assertEqual(opened, self.db)
        self.assertEqual(len(seen), 1)
        self.assertNotEqual(seen[0], "MainThread")
        self.assertNotEqual(seen[0], threading.current_thread().name)


class WatcherReloadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "engagement.sqlite"
        initialize_database(self.db, "watcher")
        add_scope_rule(self.db, "lab", "192.0.2.0/24", included=True)

    def test_reload_now_publishes_a_fresh_snapshot_off_the_ui_thread(self) -> None:
        watcher = MapSnapshotWatcher(self.db, interval=30.0)
        watcher.start()
        self.addCleanup(watcher.stop)
        first = watcher.prime(timeout=5.0)
        self.assertIsNotNone(first)

        # A quiet interval is far longer than the test, so only reload_now can
        # make the watcher notice this write.
        from lumos.core.scan_store import ScanWriter, make_scan_context
        from lumos.core.nmap.xml_stream import HostRecord

        conn = open_database(self.db, readonly=True)
        try:
            engagement_id = conn.execute("SELECT id FROM engagement").fetchone()[0]
            network_id = conn.execute("SELECT id FROM networks LIMIT 1").fetchone()[0]
        finally:
            conn.close()
        context = make_scan_context(
            engagement_id=engagement_id,
            network_id=network_id,
            targets=["192.0.2.0/24"],
            resolved_targets=["192.0.2.0/24"],
            argv=["nmap"],
            nmap_version="7.99",
            scanner_name="test",
            operator="tester",
            interface="",
            scope_override=False,
            evidence_enabled=False,
        )
        writer = ScanWriter(self.db, context)
        writer.submit_host(
            HostRecord(
                state="up",
                reason="syn-ack",
                addresses=(),
                hostnames=("late-host",),
                os_name="",
                os_accuracy=None,
                ports=(),
                scripts=(),
                hops=(),
            )
        )
        writer.finish(
            exit_code=0, status="completed", evidence=None, evidence_bytes=0, evidence_sha256=""
        )

        watcher.reload_now()
        deadline = time.monotonic() + 5.0
        latest = None
        while time.monotonic() < deadline:
            latest = watcher.take_latest()
            if latest is not None and len(latest.nodes) > len(first.nodes):
                break
            time.sleep(0.05)
        self.assertIsNotNone(latest)
        self.assertGreater(len(latest.nodes), len(first.nodes))
