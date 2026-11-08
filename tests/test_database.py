from __future__ import annotations

import os
import sqlite3
import stat
import tempfile
import unittest
import uuid
from pathlib import Path

from lumos.core.database import (
    DatabaseError,
    apply_migrations,
    check_database,
    initialize_database,
    open_database,
    validate_database,
)
from lumos.core.schema import APPLICATION_ID, SCHEMA_VERSION


class DatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.path = Path(self.tempdir.name) / "engagement.sqlite"

    def test_create_sets_identity_schema_and_private_mode(self) -> None:
        engagement_id = initialize_database(self.path, "Synthetic engagement")
        self.assertEqual(str(uuid.UUID(engagement_id)), engagement_id)
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        result = check_database(self.path)
        self.assertEqual(result["application_id"], APPLICATION_ID)
        self.assertEqual(result["user_version"], SCHEMA_VERSION)
        self.assertEqual(result["integrity"], "ok")
        self.assertGreater(result["tables"], 25)
        self.assertEqual(result["views"], 2)

    def test_database_uses_wal_foreign_keys_and_trusted_schema_off(self) -> None:
        initialize_database(self.path, "Synthetic engagement")
        conn = open_database(self.path)
        self.addCleanup(conn.close)
        self.assertEqual(conn.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
        self.assertEqual(conn.execute("PRAGMA foreign_keys").fetchone()[0], 1)
        self.assertEqual(conn.execute("PRAGMA trusted_schema").fetchone()[0], 0)
        self.assertEqual(conn.execute("PRAGMA application_id").fetchone()[0], APPLICATION_ID)
        self.assertEqual(conn.execute("PRAGMA user_version").fetchone()[0], SCHEMA_VERSION)

    def test_engagement_name_is_parameterized_data(self) -> None:
        name = "demo'); DROP TABLE engagement;--"
        initialize_database(self.path, name)
        conn = open_database(self.path, readonly=True)
        self.addCleanup(conn.close)
        self.assertEqual(conn.execute("SELECT name FROM engagement").fetchone()[0], name)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM engagement").fetchone()[0], 1)

    def test_create_refuses_to_overwrite_existing_file(self) -> None:
        self.path.write_bytes(b"keep me")
        with self.assertRaises(FileExistsError):
            initialize_database(self.path, "No overwrite")
        self.assertEqual(self.path.read_bytes(), b"keep me")

    def test_future_schema_is_refused(self) -> None:
        conn = sqlite3.connect(self.path)
        conn.execute(f"PRAGMA application_id = {APPLICATION_ID}")
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION + 1}")
        with self.assertRaisesRegex(DatabaseError, "newer than supported"):
            apply_migrations(conn)
        conn.close()

    def test_wrong_application_id_is_refused(self) -> None:
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA application_id = 12345")
        with self.assertRaisesRegex(DatabaseError, "Wrong application_id"):
            apply_migrations(conn)
        conn.close()

    def test_unexpected_trigger_is_rejected(self) -> None:
        initialize_database(self.path, "Trigger test")
        conn = sqlite3.connect(self.path)
        conn.execute(
            "CREATE TRIGGER hostile_trigger AFTER INSERT ON engagement "
            "BEGIN SELECT 1; END"
        )
        with self.assertRaisesRegex(DatabaseError, "Unexpected triggers"):
            validate_database(conn)
        conn.close()

    def test_wrong_schema_view_is_rejected(self) -> None:
        initialize_database(self.path, "View test")
        conn = sqlite3.connect(self.path)
        conn.execute("CREATE VIEW unexpected_view AS SELECT 1 AS value")
        with self.assertRaisesRegex(DatabaseError, "Unexpected view set"):
            validate_database(conn)
        conn.close()

    def test_open_missing_database_is_a_clear_error(self) -> None:
        with self.assertRaisesRegex(DatabaseError, "does not exist"):
            open_database(self.path)


if __name__ == "__main__":
    unittest.main()
