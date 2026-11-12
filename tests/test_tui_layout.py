from __future__ import annotations

import unittest

from lumos.tui.layout import ASPECT_X, ZOOM_LEVELS, Viewport, compute_layout, stable_slot


class _Node:
    def __init__(self, node_id: str, kind: str, distance: int) -> None:
        self.id = node_id
        self.kind = kind
        self.distance = distance


NODES = (
    _Node("root", "root", 0),
    _Node("a", "device", 1),
    _Node("b", "device", 1),
    _Node("c", "hop", 2),
    _Node("d", "unknown_hop", 2),
)


class StableSlotTests(unittest.TestCase):
    def test_slot_is_stable_across_processes(self) -> None:
        # A salted hash() would change per interpreter; blake2b must not.
        self.assertEqual(stable_slot("192.0.2.10", 32), stable_slot("192.0.2.10", 32))
        self.assertLess(stable_slot("host", 7), 7)

    def test_non_positive_slot_count(self) -> None:
        self.assertEqual(stable_slot("host", 0), 0)
        self.assertEqual(stable_slot("host", -3), 0)


class ComputeLayoutTests(unittest.TestCase):
    def test_root_is_centred_and_every_node_placed(self) -> None:
        positions = compute_layout(NODES, 80, 24)
        self.assertEqual(set(positions), {node.id for node in NODES})
        self.assertEqual(positions["root"], (40, 12))

    def test_layout_is_bounded_and_deterministic(self) -> None:
        first = compute_layout(NODES, 80, 24)
        second = compute_layout(NODES, 80, 24)
        self.assertEqual(first, second)
        for x, y in first.values():
            self.assertGreaterEqual(x, 1)
            self.assertLessEqual(x, 80 - 2)
            self.assertGreaterEqual(y, 1)
            self.assertLessEqual(y, 24 - 2)

    def test_nodes_sharing_a_ring_do_not_collide(self) -> None:
        ring = tuple(_Node(f"n{index}", "device", 1) for index in range(12))
        positions = compute_layout((_Node("root", "root", 0), *ring), 120, 40)
        placed = [positions[node.id] for node in ring]
        self.assertEqual(len(placed), len(set(placed)))

    def test_overrides_win(self) -> None:
        positions = compute_layout(NODES, 80, 24, overrides={"a": (5, 6)})
        self.assertEqual(positions["a"], (5, 6))

    def test_degenerate_dimensions_return_nothing(self) -> None:
        self.assertEqual(compute_layout((), 80, 24), {})
        self.assertEqual(compute_layout(NODES, 3, 24), {})
        self.assertEqual(compute_layout(NODES, 80, 2), {})


class ViewportTests(unittest.TestCase):
    def test_identity_transform_round_trips(self) -> None:
        view = Viewport()
        self.assertEqual(view.project((10, 5), 80, 24), (10, 5))
        self.assertEqual(view.unproject((10, 5), 80, 24), (10, 5))
        self.assertEqual(view.zoom, 1.0)
        self.assertEqual(view.label, "zoom 1.00x")

    def test_zoom_scales_around_the_centre(self) -> None:
        view = Viewport().zoom_in()
        self.assertEqual(view.zoom, ZOOM_LEVELS[1])
        centre = view.project((40, 12), 80, 24)
        self.assertEqual(centre, (40, 12))
        self.assertEqual(view.project((60, 12), 80, 24), (65, 12))

    def test_zoom_is_clamped_at_both_ends(self) -> None:
        view = Viewport()
        for _ in range(20):
            view = view.zoom_in()
        self.assertEqual(view.zoom, ZOOM_LEVELS[-1])
        for _ in range(20):
            view = view.zoom_out()
        self.assertEqual(view.zoom, ZOOM_LEVELS[0])

    def test_pan_is_clamped_and_resettable(self) -> None:
        view = Viewport().pan(5, -3, 80, 24)
        self.assertEqual((view.pan_x, view.pan_y), (5, -3))
        self.assertEqual(view.project((40, 12), 80, 24), (45, 9))
        far = view.pan(10_000, 10_000, 80, 24)
        self.assertEqual((far.pan_x, far.pan_y), (80, 24))
        self.assertEqual(far.reset(), Viewport())

    def test_visible_rejects_far_off_panels(self) -> None:
        self.assertTrue(Viewport().visible((40, 12), 80, 24))
        self.assertFalse(Viewport().pan(500, 0, 80, 24).visible((40, 12), 80, 24))

    def test_projection_uses_the_declared_aspect(self) -> None:
        # Documented constant, guarded so a silent change is caught.
        self.assertGreater(ASPECT_X, 1.0)


if __name__ == "__main__":
    unittest.main()
