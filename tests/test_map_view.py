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
FIXTURE = ROOT / "tests" / "fixtures" / "nmap" / "normal.xml"


class MapSnapshotTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "engagement.sqlite"
        initialize_database(self.db, "map test")

    def test_empty_engagement_uses_explicit_non_persisted_root(self) -> None:
        snapshot = load_map_snapshot(self.db)
        self.assertEqual(len(snapshot.nodes), 1)
        self.assertEqual(snapshot.nodes[0].kind, "root")
        self.assertEqual(snapshot.nodes[0].id, "pending-root")
        self.assertEqual(snapshot.nodes[0].label, "Scanner not yet recorded")
        self.assertFalse(snapshot.edges)
        output = render_plain_snapshot(snapshot)
        self.assertIn("No topology links recorded", output)
        self.assertTrue(output.isascii())
        conn = open_database(self.db, readonly=True)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM topology_nodes").fetchone()[0], 0)
        finally:
            conn.close()

    def test_fake_scan_snapshot_contains_observed_edges_and_host_details(self) -> None:
        add_scope_rule(self.db, "lab", "192.0.2.0/24", included=True, author="test")
        with patch.dict(os.environ, {"NMAP_FAKE_FIXTURE": str(FIXTURE)}):
            scan_database(self.db, "lab", ["192.0.2.10"], executable=str(FAKE), operator="test")
        snapshot = load_map_snapshot(self.db)
        node_ids = {node.id for node in snapshot.nodes}
        self.assertEqual(snapshot.active_scans, 0)
        self.assertGreaterEqual(sum(node.kind == "root" for node in snapshot.nodes), 1)
        self.assertTrue(any(node.kind == "device" for node in snapshot.nodes))
        self.assertTrue(any(node.kind in {"hop", "unknown_hop"} for node in snapshot.nodes))
        self.assertTrue(snapshot.edges)
        self.assertTrue(all(edge.from_node_id in node_ids and edge.to_node_id in node_ids for edge in snapshot.edges))
        self.assertTrue(snapshot.edges[0].source_kind)
        self.assertGreaterEqual(snapshot.edges[0].confidence, 0.0)
        self.assertIn(snapshot.edges[0].edge_type, render_plain_snapshot(snapshot))
        self.assertIn("last confirmed", render_plain_snapshot(snapshot))
        device = next(node for node in snapshot.nodes if node.kind == "device")
        self.assertTrue(device.addresses)
        self.assertGreater(device.open_ports, 0)
        self.assertGreater(snapshot.review_items, 0)

    def test_node_bound_does_not_return_edges_to_hidden_nodes(self) -> None:
        add_scope_rule(self.db, "lab", "192.0.2.0/24", included=True, author="test")
        with patch.dict(os.environ, {"NMAP_FAKE_FIXTURE": str(FIXTURE)}):
            scan_database(self.db, "lab", ["192.0.2.10"], executable=str(FAKE), operator="test")
        snapshot = load_map_snapshot(self.db, max_nodes=1)
        self.assertEqual(len(snapshot.nodes), 1)
        self.assertEqual(snapshot.nodes[0].kind, "root")
        self.assertFalse(snapshot.edges)

    def test_node_limit_must_be_positive(self) -> None:
        with self.assertRaisesRegex(ValueError, "at least 1"):
            load_map_snapshot(self.db, max_nodes=0)


if __name__ == "__main__":
    unittest.main()
