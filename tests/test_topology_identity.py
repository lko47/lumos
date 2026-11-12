from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lumos.core.database import initialize_database, open_database
from lumos.core.scanning import scan_database
from lumos.core.scope_store import add_scope_rule
from lumos.services.map_view import load_map_snapshot, render_plain_snapshot

ROOT = Path(__file__).resolve().parents[1]
FAKE = ROOT / "tests" / "fake_nmap" / "nmap"
TRACED = ROOT / "tests" / "fixtures" / "nmap" / "normal.xml"
UNTRACED = ROOT / "tests" / "fixtures" / "nmap" / "no-trace.xml"


class TopologyIdentityTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "engagement.sqlite"
        initialize_database(self.db, "topology test")
        add_scope_rule(self.db, "lab", "192.0.2.0/24", included=True, author="t")
        self.conn = open_database(self.db, readonly=True)
        self.addCleanup(self.conn.close)

    def _scan(self, fixture: Path) -> None:
        with patch.dict(os.environ, {"NMAP_FAKE_FIXTURE": str(fixture)}):
            scan_database(self.db, "lab", ["192.0.2.10"], executable=str(FAKE), operator="t")

    def _count(self, sql: str, params: tuple = ()) -> int:
        return int(self.conn.execute(sql, params).fetchone()[0])

    def test_repeated_scan_reuses_root_and_hop_nodes(self) -> None:
        self._scan(TRACED)
        self._scan(TRACED)
        self.conn.close()
        self.conn = open_database(self.db, readonly=True)
        self.assertEqual(self._count("SELECT COUNT(*) FROM topology_nodes WHERE kind = 'root'"), 1)
        self.assertEqual(self._count("SELECT COUNT(*) FROM topology_nodes WHERE kind = 'hop'"), 2)
        self.assertEqual(self._count("SELECT COUNT(*) FROM topology_nodes WHERE kind = 'unknown_hop'"), 1)
        # Devices are never auto-merged, so each scan of the same host adds one.
        self.assertEqual(self._count("SELECT COUNT(*) FROM topology_nodes WHERE kind = 'device'"), 2)
        self.assertEqual(self._count("SELECT COUNT(*) FROM vantage_points"), 1)

    def test_hop_nodes_are_keyed_on_the_address_row(self) -> None:
        self._scan(TRACED)
        self.conn.close()
        self.conn = open_database(self.db, readonly=True)
        hop_entities = [
            row[0]
            for row in self.conn.execute(
                "SELECT entity_id FROM topology_nodes WHERE kind = 'hop' ORDER BY entity_id"
            )
        ]
        self.assertTrue(hop_entities)
        placeholders = ",".join("?" for _ in hop_entities)
        address_ids = {
            row[0]
            for row in self.conn.execute(
                f"SELECT id FROM addresses WHERE id IN ({placeholders})", tuple(hop_entities)
            )
        }
        self.assertEqual(address_ids, set(hop_entities))

    def test_duplicate_edges_are_collapsed_and_reconfirmed(self) -> None:
        self._scan(TRACED)
        first = {
            (row[0], row[1], row[2], row[3])
            for row in self.conn.execute(
                "SELECT from_node_id, to_node_id, edge_type, source_kind FROM topology_edges"
            )
        }
        self.conn.close()
        self.conn = open_database(self.db, readonly=True)
        self._scan(TRACED)
        self.conn.close()
        self.conn = open_database(self.db, readonly=True)
        second = {
            (row[0], row[1], row[2], row[3])
            for row in self.conn.execute(
                "SELECT from_node_id, to_node_id, edge_type, source_kind FROM topology_edges"
            )
        }
        # The three infrastructure hops reconnect to the same nodes; only the
        # new device (no auto-merge) adds a fresh link.
        self.assertLessEqual(first, second)
        self.assertEqual(len(second - first), 1)
        confirmed = self._count(
            "SELECT COUNT(*) FROM topology_edges WHERE edge_type = 'traceroute' "
            "AND last_confirmed_at IS NOT NULL"
        )
        self.assertEqual(confirmed, self._count("SELECT COUNT(*) FROM topology_edges"))

    def test_review_items_are_reused_across_scans(self) -> None:
        self._scan(TRACED)
        self._scan(TRACED)
        self.conn.close()
        self.conn = open_database(self.db, readonly=True)
        items = self._count(
            "SELECT COUNT(*) FROM review_items WHERE reason_code = 'unresponsive_traceroute_hop'"
        )
        events = self._count(
            "SELECT COUNT(*) FROM review_events e JOIN review_items r ON r.id = e.review_item_id "
            "WHERE r.reason_code = 'unresponsive_traceroute_hop'"
        )
        self.assertEqual(items, 1)
        self.assertEqual(events, 2)

    def test_host_without_trace_gets_a_marked_inferred_link(self) -> None:
        self._scan(UNTRACED)
        row = self.conn.execute(
            "SELECT edge_type, source_kind, confidence, last_confirmed_at, author "
            "FROM topology_edges"
        ).fetchone()
        self.assertIsNotNone(row)
        self.assertEqual(row[0], "inferred")
        self.assertEqual(row[1], "inference")
        self.assertAlmostEqual(row[2], 0.35)
        self.assertIsNone(row[3], "an inference must not claim confirmation")
        snapshot = load_map_snapshot(self.db)
        self.assertEqual(len(snapshot.edges), 1)
        self.assertEqual(snapshot.edges[0].edge_type, "inferred")
        from_id = snapshot.edges[0].from_node_id
        root = next(node for node in snapshot.nodes if node.id == from_id)
        self.assertEqual(root.kind, "root")

    def test_traced_hosts_do_not_get_inferred_links(self) -> None:
        self._scan(TRACED)
        self.conn.close()
        self.conn = open_database(self.db, readonly=True)
        self.assertEqual(self._count("SELECT COUNT(*) FROM topology_edges WHERE edge_type = 'inferred'"), 0)

    def test_not_shown_counter_reports_the_hidden_nodes(self) -> None:
        self._scan(TRACED)
        self.conn.close()
        self.conn = open_database(self.db, readonly=True)
        total = self._count("SELECT COUNT(*) FROM topology_nodes")
        snapshot = load_map_snapshot(self.db, max_nodes=2)
        self.assertEqual(len(snapshot.nodes), 2)
        self.assertEqual(snapshot.not_shown, total - 2)
        self.assertIn(f"Not shown: {total - 2}", render_plain_snapshot(snapshot))
        full = load_map_snapshot(self.db)
        self.assertEqual(full.not_shown, 0)


if __name__ == "__main__":
    unittest.main()
