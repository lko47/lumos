"""Decisions on inferred links, and the plain-English evidence sentence."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lumos.core.decisions import DecisionError, describe_edge, record_decision
from lumos.core.database import open_database
from lumos.core.inference import rebuild_inferred
from test_inference import BASE_ROUTES, Scenario, eth0


class DecisionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.scan = Scenario(Path(self.tmp.name), (eth0(),), BASE_ROUTES)
        for index in range(3):
            self.scan.add_host(
                f"192.0.2.{index + 2}", reason="arp-response", mac=f"02:00:00:40:00:{index:02x}"
            )
        rebuild_inferred(self.scan.db)

    def inferred_edges(self):
        return self.scan.query("SELECT id, from_node_id, to_node_id FROM topology_edges WHERE edge_type = 'inferred'")

    def test_promote_turns_the_inferred_link_into_a_manual_one(self) -> None:
        edge = self.inferred_edges()[0]
        record_decision(self.scan.db, edge[0], "promoted", author="analyst")
        rows = self.scan.query(
            "SELECT edge_type, author, derived, source_kind FROM topology_edges "
            "WHERE from_node_id = ? AND to_node_id = ?",
            (edge[1], edge[2]),
        )
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "manual")
        self.assertEqual(rows[0][1], "analyst")
        self.assertEqual(rows[0][2], 0)
        self.assertEqual(rows[0][3], "promotion")
        decisions = self.scan.query("SELECT decision, author FROM edge_decisions")
        self.assertEqual([tuple(row) for row in decisions], [("promoted", "analyst")])
        rebuild_inferred(self.scan.db)
        again = self.scan.query(
            "SELECT edge_type, COUNT(*) FROM topology_edges WHERE from_node_id = ? AND to_node_id = ?",
            (edge[1], edge[2]),
        )
        self.assertEqual(tuple(again[0]), ("manual", 1))

    def test_reject_removes_the_link_and_the_rebuild_does_not_bring_it_back(self) -> None:
        edge = self.inferred_edges()[0]
        record_decision(self.scan.db, edge[0], "rejected", author="analyst")
        self.assertEqual(
            self.scan.query("SELECT COUNT(*) FROM topology_edges WHERE id = ?", (edge[0],))[0][0], 0
        )
        rebuild_inferred(self.scan.db)
        self.assertEqual(
            self.scan.query("SELECT COUNT(*) FROM topology_edges WHERE id = ?", (edge[0],))[0][0], 0
        )
        remaining = self.inferred_edges()
        self.assertEqual(len(remaining), 2)

    def test_observed_links_cannot_be_decided(self) -> None:
        local = self.scan.query("SELECT id FROM topology_edges WHERE edge_type = 'local'")[0][0]
        with self.assertRaises(DecisionError):
            record_decision(self.scan.db, local, "promoted")

    def test_unknown_edge_is_reported_plainly(self) -> None:
        with self.assertRaises(DecisionError):
            record_decision(self.scan.db, "no-such-edge", "rejected")


class DescribeEdgeTests(unittest.TestCase):
    def test_arp_sentence_names_the_address_network_and_interface(self) -> None:
        text = describe_edge(
            "on_link_arp",
            {"address": "192.0.2.14", "cidr": "192.0.2.0/24", "interface": "eth0", "reason": "arp-response"},
            0.95,
        )
        self.assertEqual(
            text,
            "Inferred by on_link_arp: 192.0.2.14 is inside 192.0.2.0/24 on eth0 and answered ARP. "
            "Confidence 0.95.",
        )

    def test_address_only_sentence_says_there_was_no_arp(self) -> None:
        text = describe_edge(
            "on_link_address",
            {"address": "192.0.2.15", "cidr": "192.0.2.0/24", "interface": "eth0"},
            0.70,
        )
        self.assertIn("no ARP or MAC evidence", text)
        self.assertIn("Confidence 0.70", text)

    def test_assumed_prefix_is_stated(self) -> None:
        text = describe_edge(
            "routed_via_gateway",
            {"cidr": "198.51.100.0/24", "gateway": "192.0.2.1", "assumed_prefix": True},
            0.40,
        )
        self.assertIn("assumed", text)
        self.assertIn("192.0.2.1", text)

    def test_unknown_path_sentence_is_honest(self) -> None:
        text = describe_edge("unknown_path", {"cidr": "192.0.2.0/24"}, 0.20)
        self.assertIn("No interface or route data", text)
        self.assertIn("Confidence 0.20", text)

    def test_local_interface_is_called_local_not_inferred(self) -> None:
        text = describe_edge(
            "local_interface",
            {"address": "192.0.2.32/24", "cidr": "192.0.2.0/24", "interface": "eth0"},
            1.0,
        )
        self.assertTrue(text.startswith("Local by local_interface"))
