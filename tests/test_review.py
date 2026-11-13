"""The review queue: newest event wins, decisions are append-only."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lumos.core.database import initialize_database, open_database
from lumos.services import review


class ReviewTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "review.sqlite"
        initialize_database(self.db, "review test")
        conn = open_database(self.db)
        with conn:
            engagement = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()[0]
            conn.execute(
                "INSERT INTO review_items (id, engagement_id, target_kind, target_id,"
                " reason_code, reason_detail, created_at, latest_event_at)"
                " VALUES ('r1', ?, 'topology_edge', 'e1', 'proxy_arp_suspected', 'two macs',"
                " '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
                (engagement,),
            )
            conn.execute(
                "INSERT INTO review_items (id, engagement_id, target_kind, target_id,"
                " reason_code, reason_detail, created_at, latest_event_at)"
                " VALUES ('r2', ?, 'topology_node', 'n1', 'identity_uncertain', '',"
                " '2026-01-02T00:00:00Z', '2026-01-02T00:00:00Z')",
                (engagement,),
            )
        conn.close()

    def test_items_start_unreviewed_and_newest_first(self) -> None:
        items = review.list_items(self.db)
        self.assertEqual([item.id for item in items], ["r2", "r1"])
        self.assertEqual({item.state for item in items}, {"unreviewed"})

    def test_a_decision_is_recorded_as_its_own_event(self) -> None:
        review.set_state(self.db, "r1", "confirmed", author="tester")
        review.set_state(self.db, "r1", "ignored", author="tester")
        conn = open_database(self.db, readonly=True)
        states = [
            row[0]
            for row in conn.execute(
                "SELECT state FROM review_events WHERE review_item_id = 'r1'"
                " ORDER BY created_at, rowid"
            )
        ]
        conn.close()
        self.assertEqual(states, ["confirmed", "ignored"], "history must survive")
        self.assertEqual(review.list_items(self.db, limit=5)[0].state, "ignored")

    def test_filtering_by_state_works(self) -> None:
        review.set_state(self.db, "r1", "flagged", author="t")
        self.assertEqual([item.id for item in review.list_items(self.db, state="flagged")], ["r1"])
        self.assertEqual(len(review.list_items(self.db, state="unreviewed")), 1)

    def test_the_short_summary_keeps_the_reason_and_shortens_a_long_id(self) -> None:
        item = review.ReviewItem(
            "r9", "host_observation", "3f3bdde3-4861-5d00-81db-a1b2c3d4e5f6",
            "no_port_data", "", "unreviewed", "",
        )
        self.assertIn("no_port_data", item.short_summary)
        self.assertIn("3f3bdde3", item.short_summary)
        self.assertNotIn("a1b2c3d4e5f6", item.short_summary)
        self.assertLess(len(item.short_summary), 70)

    def test_the_summary_counts_every_state(self) -> None:
        review.set_state(self.db, "r1", "confirmed", author="t")
        counts = review.states_of(self.db)
        self.assertEqual(counts["confirmed"], 1)
        self.assertEqual(counts["unreviewed"], 1)
        self.assertEqual(set(counts), set(review.ALL_STATES))

    def test_unreviewed_is_not_a_permitted_decision(self) -> None:
        with self.assertRaises(review.ReviewError):
            review.set_state(self.db, "r1", "unreviewed", author="t")

    def test_unknown_item_and_bad_limit_are_sentences(self) -> None:
        with self.assertRaises(review.ReviewError):
            review.set_state(self.db, "nope", "confirmed", author="t")
        with self.assertRaises(review.ReviewError):
            review.list_items(self.db, limit=0)
        with self.assertRaises(review.ReviewError):
            review.list_items(self.db, state="banana")


class ReviewPanelTests(unittest.TestCase):
    def test_picking_an_item_and_a_decision_records_it(self) -> None:
        from unittest import mock

        from lumos.services.review import ReviewItem
        from lumos.tui import app, render

        state = render.ViewState()
        item = ReviewItem("r1", "topology_edge", "e1", "proxy_arp_suspected", "", "unreviewed", "")
        with mock.patch.object(app.review, "list_items", return_value=(item,)), \
                mock.patch.object(app.forms, "choose", side_effect=[0, 1]), \
                mock.patch.object(app.review, "set_state") as set_state:
            set_state.return_value = ReviewItem(
                "r1", "topology_edge", "e1", "proxy_arp_suspected", "", "ignored", ""
            )
            self.assertTrue(app._review_panel(None, {}, True, Path("db.sqlite"), state))
        self.assertEqual(set_state.call_args.args[2], "ignored")
        self.assertIn("ignored", state.message)

    def test_an_empty_queue_says_so_and_changes_nothing(self) -> None:
        from unittest import mock

        from lumos.tui import app, render

        state = render.ViewState()
        with mock.patch.object(app.review, "list_items", return_value=()), \
                mock.patch.object(app.forms, "choose") as choose:
            self.assertFalse(app._review_panel(None, {}, True, Path("db.sqlite"), state))
        choose.assert_not_called()


if __name__ == "__main__":
    unittest.main()
