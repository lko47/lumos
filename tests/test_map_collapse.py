"""One machine must not look like three: duplicate devices collapse on the map."""

from __future__ import annotations

import unittest

from lumos.services.map_view import MapEdge, MapNode, collapse_duplicates


def node(node_id: str, address: str, kind: str = "device", reviews: int = 0) -> MapNode:
    return MapNode(
        id=node_id, kind=kind, label=address, addresses=(address,), os_name="",
        open_ports=0, review_count=reviews, distance=0,
    )


def edge(edge_id: str, source: str, target: str, edge_type: str = "inferred") -> MapEdge:
    return MapEdge(
        id=edge_id, from_node_id=source, to_node_id=target, edge_type=edge_type,
        source_kind="inference", source_id="", confidence=0.8,
        first_observed_at="", last_confirmed_at="", author="",
    )


class CollapseTests(unittest.TestCase):
    def test_same_address_is_one_node(self) -> None:
        nodes = [node("root", "", "root"), node("a", "10.0.0.1"), node("b", "10.0.0.1")]
        out, _edges = collapse_duplicates(nodes, ())
        devices = [item for item in out if item.kind == "device"]
        self.assertEqual(len(devices), 1)
        self.assertEqual(devices[0].duplicate_count, 2)

    def test_edges_are_rewritten_and_deduplicated(self) -> None:
        nodes = [node("root", "", "root"), node("a", "10.0.0.1"), node("b", "10.0.0.1")]
        edges = (edge("e1", "root", "a"), edge("e2", "root", "b"))
        _out, merged = collapse_duplicates(nodes, edges)
        self.assertEqual(len(merged), 1)
        self.assertEqual((merged[0].from_node_id, merged[0].to_node_id), ("root", "a"))

    def test_distinct_hosts_are_left_alone(self) -> None:
        nodes = [node("root", "", "root"), node("a", "10.0.0.1"), node("b", "10.0.0.2")]
        edges = (edge("e1", "a", "b"),)
        out, merged = collapse_duplicates(nodes, edges)
        self.assertEqual(len([item for item in out if item.kind == "device"]), 2)
        self.assertEqual([item.id for item in merged], ["e1"])

    def test_edge_between_duplicates_becomes_a_self_loop_and_is_dropped(self) -> None:
        nodes = [node("root", "", "root"), node("a", "10.0.0.1"), node("b", "10.0.0.1")]
        edges = (edge("e1", "a", "b"), edge("e2", "root", "a"))
        _out, merged = collapse_duplicates(nodes, edges)
        self.assertEqual([item.id for item in merged], ["e2"])

    def test_review_counts_add_up(self) -> None:
        nodes = [node("a", "10.0.0.1", reviews=2), node("b", "10.0.0.1", reviews=3)]
        out, _edges = collapse_duplicates(nodes, ())
        # A folded node shows the review items of every device it hides.
        self.assertEqual(out[0].review_count, 5)

    def test_nodes_without_addresses_are_kept(self) -> None:
        nodes = [node("zone", "", "zone"), node("root", "", "root")]
        out, _edges = collapse_duplicates(nodes, ())
        self.assertEqual(len(out), 2)


if __name__ == "__main__":
    unittest.main()
