"""Path highlighting and the sidebar buttons that drive it."""

from __future__ import annotations

import unittest

from lumos.services import path_view
from lumos.services.map_view import MapEdge, MapNode, MapSnapshot
from lumos.tui import app, render


def node(node_id: str, kind: str = "device") -> MapNode:
    return MapNode(
        id=node_id, kind=kind, label=node_id, addresses=(node_id,), os_name="",
        open_ports=0, review_count=0, distance=0, zone_id=f"zone-{node_id}",
    )


def edge(edge_id: str, source: str, target: str) -> MapEdge:
    return MapEdge(
        id=edge_id, from_node_id=source, to_node_id=target, edge_type="inferred",
        source_kind="inference", source_id="", confidence=0.8,
        first_observed_at="", last_confirmed_at="", author="",
    )


def snapshot() -> MapSnapshot:
    """root - a - b, plus an unrelated c hanging off root."""
    nodes = [node("root", "root"), node("a"), node("b"), node("c")]
    edges = (edge("e1", "root", "a"), edge("e2", "a", "b"), edge("e3", "root", "c"))
    return MapSnapshot(
        engagement_id="x", engagement_name="x", scans=1, active_scans=0, review_items=0,
        nodes=tuple(nodes), edges=edges,
    )


class ShortestPathTests(unittest.TestCase):
    def test_path_is_found_in_order(self) -> None:
        self.assertEqual(path_view.shortest_path(snapshot(), "root", "b"), ("root", "a", "b"))

    def test_hops_count_edges_not_nodes(self) -> None:
        path = path_view.shortest_path(snapshot(), "root", "b")
        self.assertEqual(path_view.hop_count(path), 2)

    def test_unknown_or_missing_endpoints_give_no_path(self) -> None:
        self.assertEqual(path_view.shortest_path(snapshot(), "", "b"), ())
        self.assertEqual(path_view.shortest_path(snapshot(), "root", "nope"), ())

    def test_same_node_is_a_zero_hop_path(self) -> None:
        self.assertEqual(path_view.shortest_path(snapshot(), "root", "root"), ("root",))
        self.assertEqual(path_view.hop_count(("root",)), 0)

    def test_highlighted_edges_are_the_ones_on_the_path(self) -> None:
        snap = snapshot()
        path = path_view.shortest_path(snap, "root", "b")
        self.assertEqual(path_view.path_edge_ids(snap, path), frozenset({"e1", "e2"}))

    def test_a_collapsed_hub_lengthens_or_breaks_the_path(self) -> None:
        snap = snapshot()
        # b disappears when its hub collapses: no path exists in the drawing
        trimmed = MapSnapshot(
            engagement_id="x", engagement_name="x", scans=1, active_scans=0, review_items=0,
            nodes=(node("root", "root"), node("a")), edges=(edge("e1", "root", "a"),),
        )
        self.assertTrue(path_view.shortest_path(snap, "root", "b"))
        self.assertEqual(path_view.shortest_path(trimmed, "root", "b"), ())


class UiActionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.snap = snapshot()
        self.state = render.ViewState()

    def _select(self, index: int) -> None:
        self.state.selected_kind = "node"
        self.state.selected = index

    def test_start_and_end_produce_a_highlighted_path(self) -> None:
        self._select(0)  # root
        app._ui_action(self.state, self.snap, "path_start")
        self._select(2)  # b
        app._ui_action(self.state, self.snap, "path_end")
        self.assertEqual(self.state.path_hops, 2)
        self.assertEqual(self.state.path_nodes, frozenset({"root", "a", "b"}))
        self.assertEqual(self.state.path_edges, frozenset({"e1", "e2"}))

    def test_clear_resets_everything(self) -> None:
        self._select(0)
        app._ui_action(self.state, self.snap, "path_start")
        app._ui_action(self.state, self.snap, "path_end")
        app._ui_action(self.state, self.snap, "path_clear")
        self.assertEqual(self.state.path_hops, 0)
        self.assertEqual(self.state.path_nodes, frozenset())

    def test_zone_toggle_asks_for_a_reload(self) -> None:
        self._select(1)
        zone = MapNode(
            id="zone-1", kind="zone", label="10.0.0.0/24", addresses=(), os_name="",
            open_ports=0, review_count=0, distance=0, zone_id="10.0.0.0/24",
        )
        snap = MapSnapshot(
            engagement_id="x", engagement_name="x", scans=1, active_scans=0,
            review_items=0, nodes=(zone,), edges=(),
        )
        self.state.selected = 0
        self.assertTrue(app._ui_action(self.state, snap, "zone_toggle"))
        self.assertEqual(self.state.expanded_zone, "10.0.0.0/24")
        self.assertTrue(app._ui_action(self.state, snap, "zone_toggle"))
        self.assertEqual(self.state.expanded_zone, "")

    def test_collapse_all_asks_for_a_reload(self) -> None:
        self.state.expanded_zone = "10.0.0.0/24"
        self.assertTrue(app._ui_action(self.state, self.snap, "collapse_all"))
        self.assertEqual(self.state.expanded_zone, "")

    def test_an_unknown_action_changes_nothing(self) -> None:
        self.assertFalse(app._ui_action(self.state, self.snap, "nonsense"))


if __name__ == "__main__":
    unittest.main()