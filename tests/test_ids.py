from __future__ import annotations

import sqlite3
import tempfile
import unittest
import uuid
from pathlib import Path

from lumos.core import ids
from lumos.core.scope_store import add_scope_rule
from lumos.core.database import (
    DatabaseError,
    check_database,
    initialize_database,
    open_database,
    upgrade_database,
)
from lumos.core.schema import APPLICATION_ID, MIGRATIONS, SCHEMA_VERSION


class DeterministicIdTests(unittest.TestCase):
    def test_ids_are_uuid_shaped_and_stable(self) -> None:
        first = ids.network_id("eng-uid", "lab")
        self.assertEqual(str(uuid.UUID(first)), first)
        self.assertEqual(first, ids.network_id("eng-uid", "lab"))
        self.assertNotEqual(first, ids.network_id("eng-uid", "other"))
        self.assertNotEqual(first, ids.network_id("another-uid", "lab"))

    def test_each_namespace_is_distinct(self) -> None:
        same_args = ("key",)
        made = {
            ids.network_id("u", "key"),
            ids.address_id("u", "key", "value"),
            ids.device_id("u", "key", 0),
            ids.tag_id("u", "key"),
            ids.scope_rule_id("u", "cidr", "key", True),
            ids.review_item_id("u", "key", "target", "value"),
        }
        self.assertEqual(len(made), 6)

    def test_natural_keys_separate_components(self) -> None:
        # A separator collision must not alias two different keys together.
        self.assertNotEqual(
            ids.address_id("net", "ipv4", "a b"),
            ids.address_id("net", "ipv4 a", "b"),
        )

    def test_composite_keys_include_every_component(self) -> None:
        base = ids.scope_rule_id("u", "cidr", "192.0.2.0/24", True)
        self.assertNotEqual(base, ids.scope_rule_id("u", "cidr", "192.0.2.0/24", False))
        self.assertNotEqual(base, ids.scope_rule_id("u", "range", "192.0.2.0/24", True))
        edge = ids.edge_id("u", "a", "b", "traceroute", "nmap_xml")
        self.assertNotEqual(edge, ids.edge_id("u", "b", "a", "traceroute", "nmap_xml"))


class MergeIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "engagement.sqlite"

    def test_engagement_uid_is_derived_stored_and_stable(self) -> None:
        initialize_database(self.db, "merge test")
        conn = open_database(self.db)
        self.addCleanup(conn.close)
        stored = conn.execute("SELECT value FROM meta WHERE key = 'engagement_uid'").fetchone()[0]
        name, created_at = conn.execute("SELECT name, created_at FROM engagement").fetchone()
        self.assertEqual(stored, ids.engagement_uid(name, created_at))
        self.assertEqual(ids.ensure_engagement_uid(conn), stored)
        self.assertEqual(ids.read_engagement_uid(conn), stored)
        # Reopening must not re-derive a different identity.
        conn.close()
        conn = open_database(self.db, readonly=True)
        try:
            self.assertEqual(ids.read_engagement_uid(conn), stored)
        finally:
            conn.close()

    def test_merge_accepts_the_same_engagement_only(self) -> None:
        initialize_database(self.db, "merge test")
        conn = open_database(self.db)
        self.addCleanup(conn.close)
        uid = ids.read_engagement_uid(conn)
        local_id = conn.execute("SELECT id FROM engagement").fetchone()[0]
        self.assertEqual(ids.merge_engagement_id(conn, uid), local_id)
        with self.assertRaisesRegex(ValueError, "different engagement"):
            ids.merge_engagement_id(conn, "00000000-0000-5000-8000-000000000000")

    def test_two_files_for_the_same_engagement_share_child_ids(self) -> None:
        other = Path(self.tmp.name) / "copy.sqlite"
        initialize_database(self.db, "merge test")
        initialize_database(other, "merge test")
        conn_a = open_database(self.db)
        conn_b = open_database(other)
        self.addCleanup(conn_a.close)
        self.addCleanup(conn_b.close)
        # Same name but different creation instants are different engagements.
        self.assertNotEqual(ids.read_engagement_uid(conn_a), ids.read_engagement_uid(conn_b))
        # Child ids are keyed on the uid, so they follow it exactly.
        uid_a = ids.read_engagement_uid(conn_a)
        self.assertEqual(ids.network_id(uid_a, "lab"), ids.network_id(uid_a, "lab"))


class SchemaV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "engagement.sqlite"
        initialize_database(self.db, "schema test")

    def test_identity_and_version_are_explicit(self) -> None:
        conn = open_database(self.db, readonly=True)
        self.addCleanup(conn.close)
        self.assertEqual(conn.execute("PRAGMA application_id").fetchone()[0], APPLICATION_ID)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_schema WHERE type = 'table'")}
        self.assertIn("meta", tables)
        self.assertIn("merge_log", tables)
        result = check_database(self.db)
        self.assertEqual(result["application_id"], APPLICATION_ID)
        self.assertEqual(result["user_version"], SCHEMA_VERSION)

    def test_unique_indexes_reject_duplicate_natural_keys(self) -> None:
        conn = open_database(self.db)
        self.addCleanup(conn.close)
        engagement_id = conn.execute("SELECT id FROM engagement").fetchone()[0]
        row = (engagement_id, "cidr", "192.0.2.0/24", 1, "analyst", "2026-01-01T00:00:00Z")
        conn.execute(
            "INSERT INTO scope_rules(id, engagement_id, rule_kind, rule_value, included, author, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (str(uuid.uuid4()), *row),
        )
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO scope_rules(id, engagement_id, rule_kind, rule_value, included, author, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), *row),
            )
        conn.rollback()

    def test_merge_log_records_outcomes_only_from_the_allowed_set(self) -> None:
        conn = open_database(self.db)
        self.addCleanup(conn.close)
        with self.assertRaises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO merge_log(id, applied_at, source_application_id, source_user_version, outcome) "
                "VALUES (?, '2026-01-01', ?, 2, 'silently_merged')",
                (str(uuid.uuid4()), APPLICATION_ID),
            )
        conn.rollback()

    def test_v1_file_upgrades_in_place_and_collapses_duplicates(self) -> None:
        legacy = Path(self.tmp.name) / "legacy.sqlite"
        raw = sqlite3.connect(legacy)
        raw.executescript(MIGRATIONS[1])
        raw.execute("PRAGMA user_version = 1")
        raw.execute(
            "INSERT INTO engagement(id, name, client, operator, created_at) VALUES (?, 'legacy', '', '', ?)",
            ("legacy-engagement", "2026-01-01T00:00:00.000000Z"),
        )
        uid = "11111111-1111-5111-8111-111111111111"
        raw.execute(
            "INSERT INTO networks(id, engagement_id, name, created_at) VALUES (?, 'legacy-engagement', 'lab', ?)",
            (uid, "2026-01-01T00:00:00.000000Z"),
        )
        for value in ("192.0.2.0/24", "192.0.2.0/24"):
            raw.execute(
                "INSERT INTO scope_rules(id, engagement_id, rule_kind, rule_value, included, author, created_at) "
                "VALUES (?, 'legacy-engagement', 'cidr', ?, 1, '', ?)",
                (str(uuid.uuid4()), value, "2026-01-01T00:00:00.000000Z"),
            )
        raw.commit()
        raw.close()

        result = upgrade_database(legacy)
        self.assertEqual(result["previous_user_version"], 1)
        self.assertEqual(result["user_version"], SCHEMA_VERSION)
        self.assertTrue(result["engagement_uid"])
        conn = open_database(legacy, readonly=True)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scope_rules").fetchone()[0], 1)
            self.assertIsNotNone(
                conn.execute("SELECT value FROM meta WHERE key = 'engagement_uid'").fetchone()
            )
        finally:
            conn.close()

    def test_upgrade_refuses_a_foreign_file(self) -> None:
        foreign = Path(self.tmp.name) / "foreign.sqlite"
        raw = sqlite3.connect(foreign)
        raw.executescript("PRAGMA application_id = 12345;\nCREATE TABLE engagement (id TEXT);")
        raw.commit()
        raw.close()
        with self.assertRaisesRegex(DatabaseError, "Wrong application_id"):
            upgrade_database(foreign)



class DeterministicStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "engagement.sqlite"
        initialize_database(self.db, "store test")

    def test_scope_rows_use_natural_key_ids_and_stay_idempotent(self) -> None:
        network_id, inserted = add_scope_rule(
            self.db, "lab", "192.0.2.0/24", included=True, author="analyst"
        )
        self.assertTrue(inserted)
        conn = open_database(self.db, readonly=True)
        try:
            uid = ids.read_engagement_uid(conn)
            rule_id = conn.execute("SELECT id FROM scope_rules").fetchone()[0]
        finally:
            conn.close()
        self.assertEqual(network_id, ids.network_id(uid, "lab"))
        self.assertEqual(rule_id, ids.scope_rule_id(uid, "cidr", "192.0.2.0/24", True))

        again_id, inserted_again = add_scope_rule(
            self.db, "lab", "192.0.2.0/24", included=True, author="someone-else"
        )
        self.assertEqual(again_id, network_id)
        self.assertFalse(inserted_again)
        conn = open_database(self.db, readonly=True)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scope_rules").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM networks").fetchone()[0], 1)
        finally:
            conn.close()

    def test_exclusion_rule_has_its_own_identity(self) -> None:
        add_scope_rule(self.db, "lab", "192.0.2.0/24", included=True, author="a")
        add_scope_rule(self.db, "lab", "192.0.2.0/24", included=False, author="a")
        conn = open_database(self.db, readonly=True)
        try:
            rows = conn.execute("SELECT id, included FROM scope_rules ORDER BY included").fetchall()
        finally:
            conn.close()
        self.assertEqual(len(rows), 2)
        self.assertNotEqual(rows[0][0], rows[1][0])


if __name__ == "__main__":
    unittest.main()
