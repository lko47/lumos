"""Manual nodes and links: claims that survive rebuilds and merges."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lumos.core import reports
from lumos.core.inference import rebuild_inferred
from lumos.services import demo, manual
from lumos.services.map_view import load_map_snapshot


class ManualTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "eng.sqlite"
        demo.build_demo(self.db)

    def _root(self) -> str:
        conn = sqlite3.connect(self.db)
        try:
            return str(conn.execute(
                "SELECT id FROM topology_nodes WHERE kind = 'root' LIMIT 1"
            ).fetchone()[0])
        finally:
            conn.close()

    def test_a_manual_node_appears_in_the_map_and_the_exports(self) -> None:
        node = manual.add_node(self.db, label="console switch", author="tester")
        self.assertIn("console switch", [item.label for item in manual.list_nodes(self.db)])
        self.assertIn(node.node_id, [item.id for item in load_map_snapshot(self.db).nodes])
        self.assertIn("console switch", reports.build_dot_report(self.db))
        self.assertIn("console switch", reports.build_mermaid_report(self.db))

    def test_a_manual_node_survives_an_inference_rebuild(self) -> None:
        manual.add_node(self.db, label="console switch", author="tester")
        rebuild_inferred(self.db)
        self.assertEqual([n.label for n in manual.list_nodes(self.db)], ["console switch"])

    def test_duplicate_labels_and_unknown_types_are_refused(self) -> None:
        manual.add_node(self.db, label="console switch", author="tester")
        with self.assertRaises(manual.ManualError):
            manual.add_node(self.db, label="console switch", author="tester")
        with self.assertRaises(manual.ManualError):
            manual.add_node(self.db, label="other", author="tester", node_type="router")

    def test_a_link_needs_two_real_distinct_nodes(self) -> None:
        node = manual.add_node(self.db, label="console switch", author="tester")
        with self.assertRaises(manual.ManualError):
            manual.add_link(self.db, from_node=node.node_id, to_node="nope", author="t")
        with self.assertRaises(manual.ManualError):
            manual.add_link(self.db, from_node=node.node_id, to_node=node.node_id, author="t")
        edge = manual.add_link(
            self.db, from_node=node.node_id, to_node=self._root(), author="tester"
        )
        self.assertEqual(len(manual.links(self.db)), 1)
        with self.assertRaises(manual.ManualError):
            manual.add_link(self.db, from_node=node.node_id, to_node=self._root(), author="t")
        manual.remove_link(self.db, edge)
        self.assertEqual(manual.links(self.db), ())

    def test_only_manual_things_can_be_removed_here(self) -> None:
        with self.assertRaises(manual.ManualError):
            manual.remove_node(self.db, self._root())
        node = manual.add_node(self.db, label="console switch", author="tester")
        manual.add_link(self.db, from_node=node.node_id, to_node=self._root(), author="t")
        manual.remove_node(self.db, node.node_id)
        self.assertEqual(manual.list_nodes(self.db), ())
        self.assertEqual(manual.links(self.db), ())

    def test_a_manual_link_is_drawn_as_a_manual_claim(self) -> None:
        node = manual.add_node(self.db, label="console switch", author="tester")
        manual.add_link(self.db, from_node=node.node_id, to_node=self._root(), author="t")
        self.assertIn('style="bold"', reports.build_dot_report(self.db))
        self.assertIn("==>", reports.build_mermaid_report(self.db))


if __name__ == "__main__":
    unittest.main()
