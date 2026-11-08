from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lumos.core.database import initialize_database, open_database
from lumos.core.scope_store import add_scope_rule, get_network, read_scope_rules
from lumos.core.scope import is_target_in_scope


class ScopeStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "scope.sqlite"
        initialize_database(self.db, "scope test")

    def test_rule_add_is_idempotent_and_creates_named_network(self) -> None:
        network_id, inserted = add_scope_rule(self.db, "corp", "192.0.2.0/24", included=True, author="tester")
        self.assertTrue(inserted)
        same_network, inserted_again = add_scope_rule(self.db, "corp", "192.0.2.0/24", included=True, author="tester")
        self.assertEqual(network_id, same_network)
        self.assertFalse(inserted_again)
        engagement_id, looked_up = get_network(self.db, "corp")
        self.assertEqual(looked_up, network_id)
        self.assertTrue(engagement_id)
        rules = read_scope_rules(self.db, engagement_id)
        self.assertTrue(is_target_in_scope("192.0.2.8", rules).allowed)

    def test_include_and_exclude_rules_persist(self) -> None:
        add_scope_rule(self.db, "corp", "192.0.2.0/24", included=True)
        add_scope_rule(self.db, "corp", "192.0.2.8/32", included=False)
        engagement_id, _ = get_network(self.db, "corp")
        rules = read_scope_rules(self.db, engagement_id)
        self.assertFalse(is_target_in_scope("192.0.2.8", rules).allowed)
        self.assertTrue(is_target_in_scope("192.0.2.9", rules).allowed)

    def test_network_name_is_query_parameterized(self) -> None:
        name = "corp'; DROP TABLE networks;--"
        add_scope_rule(self.db, name, "2001:db8::/32", included=True)
        _, network_id = get_network(self.db, name)
        conn = open_database(self.db, readonly=True)
        self.addCleanup(conn.close)
        self.assertEqual(conn.execute("SELECT name FROM networks WHERE id = ?", (network_id,)).fetchone()[0], name)
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM networks").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
