from __future__ import annotations

import os
import socket
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lumos.core.database import initialize_database, open_database
from lumos.core.scanning import scan_database
from lumos.core.scope_store import add_scope_rule
from lumos.services.map_view import MapEdge, edge_class, load_map_snapshot, render_plain_snapshot

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
        collapsed = load_map_snapshot(self.db)
        # Hubs are collapsed by default; the device detail lives one expand away.
        self.assertTrue(any(node.kind == "zone" for node in collapsed.nodes))
        hub = next((n.zone_id for n in collapsed.nodes if n.kind == "zone" and n.member_count), "")
        snapshot = load_map_snapshot(self.db, expanded_zone=hub)
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
        # Open ports are carried per node so the sidebar can list them; the
        # fixture's 443 is filtered and must not appear.
        self.assertEqual(device.ports, ("22/tcp",))
        self.assertIsInstance(device.review_count, int)
        self.assertGreaterEqual(device.review_count, 0)

        # The scan panel reads a dedicated projection of the scans table.
        self.assertEqual(len(snapshot.scans_detail), 1)
        scan = snapshot.scans_detail[0]
        self.assertEqual(scan.status, "completed")
        self.assertEqual(scan.targets, ("192.0.2.10",))
        self.assertEqual(scan.exit_code, 0)
        self.assertEqual(scan.operator, "test")
        self.assertEqual(scan.hosts, 1)
        self.assertIn("7.99", scan.nmap_version)
        self.assertEqual(scan.short_id, scan.id[:8])

        # The scanner root records the vantage label and any saved interfaces.
        self.assertEqual(snapshot.root_label, socket.gethostname())
        self.assertEqual(snapshot.root_interfaces, ())

    def test_empty_engagement_has_no_scan_detail_or_vantage(self) -> None:
        snapshot = load_map_snapshot(self.db)
        self.assertEqual(snapshot.scans_detail, ())
        self.assertEqual(snapshot.root_label, "")
        self.assertEqual(snapshot.root_interfaces, ())
        self.assertEqual(snapshot.nodes[0].ports, ())

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




class EdgeClassTests(unittest.TestCase):
    def edge(self, edge_type: str, confidence: float = 1.0) -> MapEdge:
        return MapEdge(
            id="e", from_node_id="a", to_node_id="b", edge_type=edge_type,
            source_kind="nmap_xml", source_id="", confidence=confidence,
            first_observed_at="", last_confirmed_at="", author="",
        )

    def test_classes_follow_evidence_not_decoration(self) -> None:
        self.assertEqual(edge_class(self.edge("local")), "local")
        self.assertEqual(edge_class(self.edge("traceroute")), "observed")
        self.assertEqual(edge_class(self.edge("alternate")), "alternate")
        self.assertEqual(edge_class(self.edge("manual")), "manual")
        self.assertEqual(edge_class(self.edge("inferred", 0.95)), "likely")
        self.assertEqual(edge_class(self.edge("inferred", 0.6)), "likely")
        self.assertEqual(edge_class(self.edge("inferred", 0.59)), "weak")
        self.assertEqual(edge_class(self.edge("inferred", 0.2)), "weak")

    def test_only_inferred_links_can_ever_be_dotted(self) -> None:
        for edge_type in ("traceroute", "alternate", "manual", "local", "imported"):
            self.assertNotIn(edge_class(self.edge(edge_type)), {"likely", "weak"})


if __name__ == "__main__":
    unittest.main()
