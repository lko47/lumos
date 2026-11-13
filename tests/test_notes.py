"""Notes are human judgement stored verbatim, apart from terminal safety."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lumos.core.database import initialize_database
from lumos.services import notes


class NoteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "notes.sqlite"
        initialize_database(self.db, "notes")

    def test_a_note_round_trips(self) -> None:
        written = notes.add_note(
            self.db, target_kind="topology_node", target_id="node-1",
            body="port 22 is the jump host", author="tester",
        )
        found = notes.latest_note(self.db, "topology_node", "node-1")
        self.assertIsNotNone(found)
        self.assertEqual(found.body, "port 22 is the jump host")
        self.assertEqual(found.id, written.id)

    def test_an_engagement_note_needs_no_target(self) -> None:
        notes.add_note(self.db, target_kind="engagement", target_id="", body="scope signed", author="x")
        self.assertEqual(notes.latest_note(self.db, "engagement", "").body, "scope signed")

    def test_terminal_escapes_are_stripped(self) -> None:
        note = notes.add_note(
            self.db, target_kind="engagement", target_id="",
            body="evil \x1b[2Jname", author="x",
        )
        self.assertNotIn("\x1b", note.body)

    def test_empty_and_oversized_notes_are_refused(self) -> None:
        with self.assertRaises(notes.NoteError):
            notes.add_note(self.db, target_kind="engagement", target_id="", body="   ", author="x")
        with self.assertRaises(notes.NoteError):
            notes.add_note(self.db, target_kind="engagement", target_id="",
                           body="x" * (notes.MAX_NOTE_CHARS + 1), author="x")

    def test_unknown_target_kind_is_refused(self) -> None:
        with self.assertRaises(notes.NoteError):
            notes.add_note(self.db, target_kind="host", target_id="a", body="x", author="x")

    def test_a_node_note_needs_an_id(self) -> None:
        with self.assertRaises(notes.NoteError):
            notes.add_note(self.db, target_kind="topology_node", target_id="", body="x", author="x")

    def test_listing_is_newest_first_and_filterable(self) -> None:
        notes.add_note(self.db, target_kind="topology_node", target_id="a", body="first", author="x")
        notes.add_note(self.db, target_kind="topology_node", target_id="b", body="second", author="x")
        everything = notes.notes_for(self.db)
        self.assertEqual([note.body for note in everything], ["second", "first"])
        only_b = notes.notes_for(self.db, target_kind="topology_node", target_id="b")
        self.assertEqual([note.body for note in only_b], ["second"])

    def test_summary_is_the_first_line_only(self) -> None:
        note = notes.add_note(
            self.db, target_kind="engagement", target_id="",
            body="headline\nsecond line", author="x",
        )
        self.assertEqual(note.summary, "headline")


if __name__ == "__main__":
    unittest.main()


class NoteFoldTests(unittest.TestCase):
    """A folded duplicate must not lose the note someone wrote on it."""

    def _node(self, node_id: str, address: str, note: str):
        from lumos.services.map_view import MapNode

        return MapNode(
            id=node_id, kind="device", label=node_id, addresses=(address,), os_name="",
            open_ports=0, review_count=0, distance=0, note=note,
        )

    def test_notes_from_folded_duplicates_are_joined(self) -> None:
        from lumos.services.map_view import collapse_duplicates

        nodes = [
            self._node("a", "192.0.2.5", "seen by the first scan"),
            self._node("b", "192.0.2.5", "ssh banner looks like a jump box"),
        ]
        folded, _edges = collapse_duplicates(nodes, ())
        self.assertEqual(len(folded), 1)
        self.assertIn("first scan", folded[0].note)
        self.assertIn("jump box", folded[0].note)

    def test_the_same_note_twice_is_not_repeated(self) -> None:
        from lumos.services.map_view import collapse_duplicates

        nodes = [
            self._node("a", "192.0.2.5", "same"),
            self._node("b", "192.0.2.5", "same"),
        ]
        folded, _edges = collapse_duplicates(nodes, ())
        self.assertEqual(folded[0].note, "same")


class TuiNoteTests(unittest.TestCase):
    """`b` in the interface: prompt, store, ask for a redraw - or explain why not."""

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

    def test_a_typed_note_is_stored_against_the_selected_node(self) -> None:
        from unittest import mock

        from lumos.tui import app

        self.state.selected_kind = "node"
        self.state.selected = 0
        with mock.patch.object(app.forms, "text_prompt", return_value="this is a jump box"), \
                mock.patch.object(app.notes, "add_note") as add_note:
            self.assertTrue(app._note_on_selection(
                None, {}, True, Path("db.sqlite"), self.state, self.snapshot))
        add_note.assert_called_once()
        self.assertEqual(add_note.call_args.kwargs["target_id"], "node-1")
        self.assertEqual(add_note.call_args.kwargs["body"], "this is a jump box")

    def test_cancelling_changes_nothing(self) -> None:
        from unittest import mock

        from lumos.tui import app

        self.state.selected_kind = "node"
        self.state.selected = 0
        with mock.patch.object(app.forms, "text_prompt", return_value=None), \
                mock.patch.object(app.notes, "add_note") as add_note:
            self.assertFalse(app._note_on_selection(
                None, {}, True, Path("db.sqlite"), self.state, self.snapshot))
        add_note.assert_not_called()

    def test_without_a_selection_it_says_so(self) -> None:
        from lumos.tui import app

        self.state.selected_kind = "edge"
        self.assertFalse(app._note_on_selection(
            None, {}, True, Path("db.sqlite"), self.state, self.snapshot))
