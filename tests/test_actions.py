"""Writable actions are exercised headlessly: no curses, no real network."""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lumos.core import state
from lumos.core.database import initialize_database, open_database
from lumos.core.scope_store import add_scope_rule
from lumos.services import actions

ROOT = Path(__file__).resolve().parents[1]
FAKE = ROOT / "tests" / "fake_nmap" / "nmap"
FIXTURE = ROOT / "tests" / "fixtures" / "nmap" / "normal.xml"


class ActionsTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.state_home = self.dir / "state"
        patcher = patch.dict(os.environ, {"XDG_STATE_HOME": str(self.state_home)})
        patcher.start()
        self.addCleanup(patcher.stop)

    def make_database(self, name: str = "engagement.sqlite") -> Path:
        db = self.dir / name
        initialize_database(db, "actions test")
        return db


class CreateEngagementTests(ActionsTestCase):
    def test_creates_owner_only_database_and_remembers_it(self) -> None:
        db = self.dir / "new.sqlite"
        result = actions.create_engagement(db, "Client lab", client="Acme", operator="analyst")
        self.assertTrue(result.ok, result.message)
        self.assertEqual(stat.S_IMODE(db.stat().st_mode), 0o600)
        conn = open_database(db, readonly=True)
        try:
            row = conn.execute("SELECT name, client, operator FROM engagement").fetchone()
        finally:
            conn.close()
        self.assertEqual(tuple(row), ("Client lab", "Acme", "analyst"))
        self.assertEqual(actions.recent_engagements()[0]["path"], str(db))

    def test_refuses_to_overwrite_and_requires_a_name(self) -> None:
        db = self.make_database()
        self.assertFalse(actions.create_engagement(db, "again").ok)
        self.assertFalse(actions.create_engagement(self.dir / "other.sqlite", "  ").ok)

    def test_open_reports_missing_and_valid_databases(self) -> None:
        self.assertFalse(actions.open_engagement(self.dir / "nope.sqlite").ok)
        self.assertTrue(actions.open_engagement(self.make_database()).ok)

    def test_recents_drop_missing_files(self) -> None:
        db = self.make_database()
        actions.open_engagement(db)
        db.unlink()
        entries = actions.recent_engagements()
        self.assertEqual(len(entries), 1)
        self.assertFalse(entries[0]["exists"])
        state.forget_engagement(entries[0]["path"])
        self.assertEqual(actions.recent_engagements(), [])


class ScopeTests(ActionsTestCase):
    def test_add_list_and_remove_rules(self) -> None:
        db = self.make_database()
        self.assertTrue(actions.add_scope(db, "198.51.100.0/24", author="analyst").ok)
        duplicate = actions.add_scope(db, "198.51.100.0/24")
        self.assertIn("already present", duplicate.message)
        entries = actions.scope_entries(db).payload
        self.assertEqual([entry["value"] for entry in entries], ["198.51.100.0/24"])
        self.assertTrue(actions.remove_scope(db, entries[0]["id"]).ok)
        self.assertEqual(actions.scope_entries(db).payload, [])

    def test_invalid_and_empty_targets_are_refused(self) -> None:
        db = self.make_database()
        self.assertFalse(actions.add_scope(db, "not an address").ok)
        self.assertFalse(actions.add_scope(db, "   ").ok)

    def test_scope_values_lists_includes_only(self) -> None:
        db = self.make_database()
        add_scope_rule(db, "lab", "198.51.100.0/24", included=True)
        add_scope_rule(db, "lab", "198.51.100.7", included=False)
        self.assertEqual(actions.scope_values(db), ("198.51.100.0/24",))


class ScanTests(ActionsTestCase):
    def test_preview_marks_out_of_scope_targets_and_the_phrase(self) -> None:
        db = self.make_database()
        add_scope_rule(db, "lab", "198.51.100.0/24", included=True)
        inside = actions.preview_scan(db, ["198.51.100.10"], network="lab")
        self.assertTrue(inside.ok)
        self.assertEqual(inside.payload["outside"], [])
        outside = actions.preview_scan(db, ["10.9.9.9"], network="lab")
        self.assertEqual(outside.payload["outside"], ["10.9.9.9"])
        self.assertEqual(outside.payload["phrase"], "SCAN OUT OF SCOPE: 10.9.9.9")

    def test_preview_applies_the_chosen_preset(self) -> None:
        db = self.make_database()
        add_scope_rule(db, "lab", "198.51.100.0/24", included=True)
        preview = actions.preview_scan(db, ["198.51.100.10"], network="lab", preset="service")
        self.assertEqual(preview.payload["options"], "-sV --top-ports 100")

    def test_scan_job_reports_events_and_finishes(self) -> None:
        db = self.make_database()
        add_scope_rule(db, "lab", "192.0.2.0/24", included=True)
        with patch.dict(os.environ, {"NMAP_FAKE_FIXTURE": str(FIXTURE)}):
            job = actions.ScanJob(
                db,
                ["192.0.2.10"],
                network="lab",
                options="-sT",
                executable=str(FAKE),
            ).start()
            deadline = 30.0
            import time

            started = time.monotonic()
            outcome = None
            while time.monotonic() - started < deadline:
                for kind, payload in job.drain():
                    if kind == "done":
                        outcome = payload
                if outcome is not None:
                    break
                time.sleep(0.05)
        self.assertIsNotNone(outcome, "scan job never finished")
        self.assertTrue(outcome.ok, outcome.message)
        self.assertGreaterEqual(outcome.payload["hosts"], 1)


class ReportAndMaintenanceTests(ActionsTestCase):
    def test_report_refuses_overwrite_until_asked(self) -> None:
        db = self.make_database()
        target = self.dir / "reports" / "r.md"
        self.assertTrue(actions.write_report(db, target).ok)
        self.assertFalse(actions.write_report(db, target).ok)
        self.assertTrue(actions.write_report(db, target, overwrite=True).ok)
        self.assertTrue(target.is_file())

    def test_default_report_path_lives_beside_the_database(self) -> None:
        db = self.make_database()
        path = actions.default_report_path(db, "svg")
        self.assertEqual(path.parent, db.parent / "reports")
        self.assertEqual(path.suffix, ".svg")

    def test_check_upgrade_rebuild_and_merge(self) -> None:
        db = self.make_database()
        self.assertIn("schema 3", actions.check(db).message)
        self.assertTrue(actions.upgrade(db).ok)
        self.assertTrue(actions.rebuild(db).ok)
        copy = self.dir / "copy.sqlite"
        copy.write_bytes(db.read_bytes())
        preview = actions.merge(db, copy, dry_run=True)
        self.assertTrue(preview.ok, preview.message)
        self.assertFalse(actions.merge(db, self.make_database("other.sqlite")).ok)

    def test_import_xml_uses_the_fixture(self) -> None:
        db = self.make_database()
        result = actions.import_xml(db, FIXTURE, network="lab")
        self.assertTrue(result.ok, result.message)
        self.assertGreaterEqual(result.payload["hosts"], 1)

    def test_activity_log_is_bounded_and_writable(self) -> None:
        log = actions.ActivityLog(limit=3)
        for index in range(5):
            log.add("info", f"event {index}")
        self.assertEqual(len(log.entries), 3)
        written = log.write_to(self.dir / "log.txt")
        self.assertEqual(len(written.read_text().splitlines()), 3)
