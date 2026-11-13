"""Several engagement files in one view: tagged, bounded, never merged."""

from __future__ import annotations

import unittest
from pathlib import Path
from unittest import mock

from lumos.services import workspace
from lumos.services.map_view import MapEdge, MapNode, MapSnapshot


def node(node_id: str, label: str, kind: str = "device", addresses=("10.0.0.5",)) -> MapNode:
    return MapNode(
        id=node_id, kind=kind, label=label, addresses=addresses, os_name="",
        open_ports=0, review_count=0, distance=0,
    )


def edge(edge_id: str, source: str, target: str) -> MapEdge:
    return MapEdge(
        id=edge_id, from_node_id=source, to_node_id=target, edge_type="inferred",
        source_kind="inference", source_id="", confidence=0.8,
        first_observed_at="", last_confirmed_at="", author="",
    )


def snapshot(name: str, nodes, edges=()) -> MapSnapshot:
    return MapSnapshot(
        engagement_id=name, engagement_name=name, scans=1, active_scans=0,
        review_items=0, nodes=tuple(nodes), edges=tuple(edges), root_label="root",
    )


class TaggingTests(unittest.TestCase):
    def test_ids_are_prefixed_and_the_root_is_labelled(self) -> None:
        member = workspace.WorkspaceMember(path="a.sqlite", tag="s1", name="site-a")
        nodes, edges = workspace._tag(
            snapshot("site-a", [node("r", "scanner", "root", ()), node("d", "10.0.0.5")],
                     [edge("e", "r", "d")]),
            member,
        )
        self.assertEqual([item.id for item in nodes], ["s1.r", "s1.d"])
        self.assertEqual(nodes[0].label, "[site-a] scanner")
        self.assertEqual(nodes[1].label, "10.0.0.5")
        self.assertEqual(nodes[1].source_tag, "s1")
        self.assertEqual(edges[0].from_node_id, "s1.r")

    def test_duplicate_paths_are_collapsed_and_members_capped(self) -> None:
        members = workspace.members_for(["a.sqlite", "a.sqlite", "b.sqlite"])
        self.assertEqual([member.tag for member in members], ["s1", "s2"])
        many = workspace.members_for([f"{index}.sqlite" for index in range(20)])
        self.assertEqual(len(many), workspace.MAX_MEMBERS)


class BridgeTests(unittest.TestCase):
    def test_shared_address_links_the_clusters(self) -> None:
        one = snapshot("a", [node("d", "10.0.0.5")])
        two = snapshot("b", [node("d", "10.0.0.5")])
        parts = []
        for member_name, item in (("a", one), ("b", two)):
            member = workspace.WorkspaceMember(path=member_name, tag=member_name, name=member_name)
            nodes, edges = workspace._tag(item, member)
            parts.append((nodes, edges, member))
        bridges = workspace._bridges(parts)
        self.assertEqual(len(bridges), 1)
        self.assertTrue(bridges[0].bridge)
        self.assertEqual(bridges[0].edge_type, workspace.SHARED_EDGE)
        self.assertEqual(
            {bridges[0].from_node_id, bridges[0].to_node_id}, {"a.d", "b.d"}
        )

    def test_private_addresses_are_not_bridged_across_files(self) -> None:
        one = snapshot("a", [node("d", "10.0.0.5", addresses=("10.0.0.5",))])
        two = snapshot("b", [node("d", "10.0.0.6", addresses=("10.0.0.6",))])
        parts = []
        for member_name, item in (("a", one), ("b", two)):
            member = workspace.WorkspaceMember(path=member_name, tag=member_name, name=member_name)
            nodes, edges = workspace._tag(item, member)
            parts.append((nodes, edges, member))
        self.assertEqual(workspace._bridges(parts), [])


class LoadTests(unittest.TestCase):
    def test_two_files_are_combined_and_bounded(self) -> None:
        first = snapshot("site-a", [node("d", "10.0.0.5", addresses=("10.0.0.5",))],
                         [edge("e", "d", "d")])
        second = snapshot("site-b", [node("d", "10.0.0.9", addresses=("10.0.0.9",))])
        with mock.patch.object(workspace, "load_map_snapshot", side_effect=[first, second]):
            combined = workspace.load_workspace_snapshot(["a.sqlite", "b.sqlite"])
        self.assertEqual(len(combined.nodes), 2)
        self.assertEqual([tag for tag, _name in combined.members], ["s1", "s2"])
        self.assertEqual(combined.scans, 2)
        self.assertEqual(workspace.shared_address_count(combined), 0)

    def test_missing_engagement_name_falls_back_to_the_file_name(self) -> None:
        self.assertEqual(workspace.engagement_name("/tmp/no-such-file.sqlite"), "no-such-file")


if __name__ == "__main__":
    unittest.main()


class TuiWiringTests(unittest.TestCase):
    def test_single_file_uses_the_plain_loader(self) -> None:
        from lumos.tui import app

        with mock.patch.object(app, "load_map_snapshot", return_value="plain") as loader:
            self.assertEqual(app._workspace_or_file(Path("a.sqlite"), []), "plain")
        loader.assert_called_once()

    def test_members_switch_to_the_workspace_loader(self) -> None:
        from lumos.tui import app

        with mock.patch.object(app.workspace, "load_workspace_snapshot",
                               return_value="combined") as loader:
            self.assertEqual(app._workspace_or_file(Path("a.sqlite"), ["b.sqlite"]), "combined")
        loader.assert_called_once()
        self.assertEqual(loader.call_args[0][0], ["a.sqlite", "b.sqlite"])
