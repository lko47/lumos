"""Merge acceptance: no duplicates, and decisions survive a merge."""

from __future__ import annotations

import shutil
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lumos.core.decisions import record_decision
from lumos.core.database import open_database
from lumos.core.inference import rebuild_inferred
from lumos.core.merge import MergeError, merge_engagement
from test_inference import BASE_ROUTES, Scenario, eth0


class MergeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.scan = Scenario(self.dir, (eth0(),), BASE_ROUTES)
        for index in range(4):
            self.scan.add_host(
                f"198.51.100.{index + 2}", reason="arp-response", mac=f"02:00:00:60:00:{index:02x}"
            )
        rebuild_inferred(self.scan.db)

    def counts(self, path: Path | None = None) -> dict[str, int]:
        conn = open_database(path or self.scan.db, readonly=True)
        try:
            return {
                table: conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                for table in ("topology_nodes", "topology_edges", "zones", "zone_memberships", "devices")
            }
        finally:
            conn.close()

    def test_merging_a_copy_adds_no_duplicate_hubs_or_edges(self) -> None:
        before = self.counts()
        copy = self.dir / "copy.sqlite"
        shutil.copyfile(self.scan.db, copy)
        merge_engagement(self.scan.db, copy, operator="analyst")
        self.assertEqual(self.counts(), before)
        merge_engagement(self.scan.db, copy, operator="analyst")
        self.assertEqual(self.counts(), before)

    def test_merging_a_different_engagement_is_rejected_and_logged(self) -> None:
        from lumos.core.database import initialize_database

        other = self.dir / "other.sqlite"
        initialize_database(other, "someone else")
        with self.assertRaises(MergeError):
            merge_engagement(self.scan.db, other)
        conn = open_database(self.scan.db, readonly=True)
        try:
            rows = conn.execute("SELECT outcome FROM merge_log ORDER BY applied_at").fetchall()
        finally:
            conn.close()
        self.assertEqual([row[0] for row in rows], ["rejected"])

    def test_a_rejected_link_stays_gone_after_merging_a_copy_that_has_it(self) -> None:
        edge = self.scan.query("SELECT id FROM topology_edges WHERE edge_type = 'inferred' LIMIT 1")[0][0]
        copy = self.dir / "copy.sqlite"
        shutil.copyfile(self.scan.db, copy)  # copy still contains the inferred edge
        record_decision(self.scan.db, edge, "rejected", author="analyst")
        merge_engagement(self.scan.db, copy, operator="analyst")
        self.assertEqual(
            self.scan.query("SELECT COUNT(*) FROM topology_edges WHERE id = ?", (edge,))[0][0], 0
        )

    def test_a_promoted_link_stays_manual_after_merging(self) -> None:
        edge = self.scan.query(
            "SELECT id, from_node_id, to_node_id FROM topology_edges WHERE edge_type = 'inferred' LIMIT 1"
        )[0]
        copy = self.dir / "copy.sqlite"
        shutil.copyfile(self.scan.db, copy)
        record_decision(self.scan.db, edge[0], "promoted", author="analyst")
        merge_engagement(self.scan.db, copy, operator="analyst")
        rows = self.scan.query(
            "SELECT edge_type, COUNT(*) FROM topology_edges WHERE from_node_id = ? AND to_node_id = ? "
            "GROUP BY edge_type",
            (edge[1], edge[2]),
        )
        self.assertEqual([tuple(row) for row in rows], [("manual", 1)])

    def test_dry_run_changes_nothing(self) -> None:
        before = self.counts()
        copy = self.dir / "copy.sqlite"
        shutil.copyfile(self.scan.db, copy)
        stats = merge_engagement(self.scan.db, copy, dry_run=True)
        self.assertTrue(stats.dry_run)
        self.assertFalse(stats.applied)
        self.assertEqual(self.counts(), before)
        conn = open_database(self.scan.db, readonly=True)
        try:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM merge_log WHERE outcome = 'dry_run'").fetchone()[0], 1
            )
        finally:
            conn.close()

    def merge_outcomes(self) -> list[str]:
        conn = open_database(self.scan.db, readonly=True)
        try:
            return [row[0] for row in conn.execute("SELECT outcome FROM merge_log ORDER BY rowid")]
        finally:
            conn.close()

    def mutated_copy(self, name: str, *statements: str) -> Path:
        copy = self.dir / name
        shutil.copyfile(self.scan.db, copy)
        conn = sqlite3.connect(copy)
        try:
            for statement in statements:
                conn.execute(statement)
            conn.commit()
        finally:
            conn.close()
        return copy

    def test_source_with_a_newer_schema_version_is_rejected_and_logged(self) -> None:
        copy = self.mutated_copy("newer.sqlite", "PRAGMA user_version = 99")
        with self.assertRaisesRegex(MergeError, "schema version 99"):
            merge_engagement(self.scan.db, copy)
        self.assertEqual(self.merge_outcomes(), ["rejected"])

    def test_source_with_a_foreign_application_id_is_rejected_and_logged(self) -> None:
        copy = self.mutated_copy("foreign.sqlite", "PRAGMA application_id = 1234")
        with self.assertRaisesRegex(MergeError, "application_id"):
            merge_engagement(self.scan.db, copy)
        self.assertEqual(self.merge_outcomes(), ["rejected"])

    def test_source_with_an_extra_column_is_rejected_instead_of_narrowed(self) -> None:
        copy = self.mutated_copy(
            "extra-column.sqlite", "ALTER TABLE networks ADD COLUMN secret_note TEXT"
        )
        with self.assertRaisesRegex(MergeError, "columns differ for networks"):
            merge_engagement(self.scan.db, copy)
        self.assertEqual(self.merge_outcomes(), ["rejected"])

    def test_source_with_an_extra_table_or_trigger_is_rejected(self) -> None:
        copy = self.mutated_copy("extra-table.sqlite", "CREATE TABLE smuggled (x INTEGER)")
        with self.assertRaisesRegex(MergeError, "table set differs"):
            merge_engagement(self.scan.db, copy)
        copy = self.mutated_copy(
            "trigger.sqlite",
            "CREATE TRIGGER hostile AFTER INSERT ON notes BEGIN SELECT 1; END",
        )
        with self.assertRaisesRegex(MergeError, "triggers"):
            merge_engagement(self.scan.db, copy)
