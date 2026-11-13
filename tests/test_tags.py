"""Tags are names plus links, normalised for matching but spelled as written."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lumos.core.database import initialize_database
from lumos.services import tags


class TagTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "tags.sqlite"
        initialize_database(self.db, "tags")

    def _add(self, name: str, object_id: str = "node-1", kind: str = "topology_node") -> tags.Tag:
        return tags.add_tag(
            self.db, name=name, object_kind=kind, object_id=object_id, author="tester"
        )

    def test_a_tag_round_trips(self) -> None:
        self._add("dmz")
        self.assertEqual([tag.name for tag in tags.tags_for(self.db, "topology_node", "node-1")], ["dmz"])

    def test_case_variants_are_the_same_tag_but_keep_the_first_spelling(self) -> None:
        self._add("DMZ")
        self._add("dmz", object_id="node-2")
        self.assertEqual(len(tags.all_tags(self.db)), 1)
        self.assertEqual(tags.all_tags(self.db)[0].name, "DMZ")
        self.assertEqual(tags.all_tags(self.db)[0].count, 2)

    def test_applying_the_same_tag_twice_is_a_no_op(self) -> None:
        self._add("dmz")
        self._add("dmz")
        self.assertEqual(len(tags.all_tags(self.db)[0].count and tags.all_tags(self.db)), 1)
        self.assertEqual(tags.all_tags(self.db)[0].count, 1)

    def test_removal_detaches_and_garbage_collects_the_name(self) -> None:
        self._add("dmz")
        self.assertTrue(tags.remove_tag(
            self.db, name="DMZ", object_kind="topology_node", object_id="node-1"))
        self.assertEqual(tags.tags_for(self.db, "topology_node", "node-1"), ())
        self.assertEqual(tags.all_tags(self.db), ())

    def test_removing_something_absent_is_false_not_an_error(self) -> None:
        self.assertFalse(tags.remove_tag(
            self.db, name="nope", object_kind="topology_node", object_id="node-1"))

    def test_empty_and_oversized_names_are_refused(self) -> None:
        with self.assertRaises(tags.TagError):
            self._add("   ")
        with self.assertRaises(tags.TagError):
            self._add("x" * (tags.MAX_TAG_CHARS + 1))

    def test_unknown_object_kind_is_refused(self) -> None:
        with self.assertRaises(tags.TagError):
            self._add("dmz", kind="host")

    def test_terminal_escapes_are_stripped(self) -> None:
        tag = self._add("evil\x1b[2J")
        self.assertNotIn("\x1b", tag.name)

    def test_the_per_object_cap_is_enforced(self) -> None:
        for index in range(tags.MAX_TAGS_PER_OBJECT):
            self._add(f"tag-{index}")
        with self.assertRaises(tags.TagError):
            self._add("one-too-many")


class TuiTagTests(unittest.TestCase):
    """`y` in the interface tags the selected node."""

    def setUp(self) -> None:
        from lumos.services.map_view import MapNode, MapSnapshot
        from lumos.tui import render

        self.state = render.ViewState()
        self.snapshot = MapSnapshot(
            engagement_id="x", engagement_name="x", scans=1, active_scans=0, review_items=0,
            nodes=(MapNode(
                id="node-1", kind="device", label="192.0.2.10", addresses=("192.0.2.10",),
                os_name="", open_ports=0, review_count=0, distance=0,
            ),),
            edges=(),
        )

    def test_a_comma_separated_answer_attaches_every_tag(self) -> None:
        from unittest import mock

        from lumos.tui import app

        self.state.selected_kind = "node"
        self.state.selected = 0
        with mock.patch.object(app.forms, "text_prompt", return_value="dmz, jump-host"), \
                mock.patch.object(app.tags, "add_tag") as add_tag:
            self.assertTrue(app._tag_on_selection(
                None, {}, True, Path("db.sqlite"), self.state, self.snapshot))
        self.assertEqual(add_tag.call_count, 2)
        self.assertEqual(
            sorted(call.kwargs["name"] for call in add_tag.call_args_list),
            ["dmz", "jump-host"],
        )

    def test_cancelling_changes_nothing(self) -> None:
        from unittest import mock

        from lumos.tui import app

        self.state.selected_kind = "node"
        self.state.selected = 0
        with mock.patch.object(app.forms, "text_prompt", return_value=None), \
                mock.patch.object(app.tags, "add_tag") as add_tag:
            self.assertFalse(app._tag_on_selection(
                None, {}, True, Path("db.sqlite"), self.state, self.snapshot))
        add_tag.assert_not_called()


if __name__ == "__main__":
    unittest.main()
