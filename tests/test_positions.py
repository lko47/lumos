"""Pins are fractions of the map panel, so they survive a resize."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lumos.core.database import initialize_database, open_database
from lumos.services import positions


class PositionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "pins.sqlite"
        initialize_database(self.db, "pins")
        conn = open_database(self.db)
        with conn:
            engagement = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()[0]
            conn.execute(
                "INSERT INTO topology_nodes (id, engagement_id, kind, entity_id, label, created_at)"
                " VALUES ('node-1', ?, 'device', 'dev-1', '192.0.2.10', '2026-01-01T00:00:00Z')",
                (engagement,),
            )
        conn.close()

    def test_a_pin_round_trips(self) -> None:
        positions.pin_node(self.db, node_id="node-1", x=0.25, y=0.5, author="tester")
        self.assertEqual(positions.load_pins(self.db), {"node-1": (0.25, 0.5)})

    def test_pinning_twice_replaces_rather_than_duplicates(self) -> None:
        positions.pin_node(self.db, node_id="node-1", x=0.1, y=0.1, author="t")
        positions.pin_node(self.db, node_id="node-1", x=0.9, y=0.8, author="t")
        self.assertEqual(positions.load_pins(self.db), {"node-1": (0.9, 0.8)})

    def test_releasing_a_pin_removes_it_from_the_loaded_set(self) -> None:
        positions.pin_node(self.db, node_id="node-1", x=0.5, y=0.5, author="t")
        self.assertTrue(positions.unpin_node(self.db, "node-1"))
        self.assertEqual(positions.load_pins(self.db), {})
        self.assertFalse(positions.unpin_node(self.db, "node-1"))

    def test_out_of_range_or_non_finite_coordinates_are_refused(self) -> None:
        for x, y in ((1.4, 0.5), (-0.1, 0.5), (0.5, float("nan")), (float("inf"), 0.5)):
            with self.assertRaises(positions.PositionError):
                positions.pin_node(self.db, node_id="node-1", x=x, y=y, author="t")

    def test_an_unknown_node_is_refused(self) -> None:
        with self.assertRaises(positions.PositionError):
            positions.pin_node(self.db, node_id="nope", x=0.5, y=0.5, author="t")

    def test_fractions_become_grid_cells_for_the_current_size(self) -> None:
        overrides = positions.overrides_for({"node-1": (0.5, 1.0)}, width=21, height=11)
        self.assertEqual(overrides["node-1"], (10, 10))

    def test_a_fraction_round_trips_through_the_grid(self) -> None:
        x, y = positions.fraction_at((10, 10), 21, 11)
        self.assertEqual((round(x, 3), round(y, 3)), (0.5, 1.0))


if __name__ == "__main__":
    unittest.main()
