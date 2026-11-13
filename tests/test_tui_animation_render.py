"""The map animates: flow dots on measured links, ripples on new nodes, pulse."""

from __future__ import annotations

import unittest
from types import SimpleNamespace

from lumos.tui import animation, map_render, render


class GridWindow:
    """Recording window double: keeps a character grid, ignores colour."""

    def __init__(self, height: int = 24, width: int = 90) -> None:
        self.height = height
        self.width = width
        self.grid = [[" "] * width for _ in range(height)]

    def getmaxyx(self) -> tuple[int, int]:
        return self.height, self.width

    def addnstr(self, y: int, x: int, text: str, width: int, _attr: int = 0) -> None:
        if y < 0 or y >= self.height or x < 0:
            return
        for offset, char in enumerate(text[:width]):
            if x + offset >= self.width:
                break
            self.grid[y][x + offset] = char

    def chgat(self, y: int, x: int, num: int, _attr: int) -> None:
        pass

    def refresh(self) -> None:
        pass

    def cells(self) -> dict[tuple[int, int], str]:
        return {
            (x, y): char
            for y, row in enumerate(self.grid)
            for x, char in enumerate(row)
            if char != " "
        }


def snapshot(edge_type: str = "traceroute", derived: bool = False) -> SimpleNamespace:
    nodes = [
        SimpleNamespace(
            id="root", label="scanner", kind="root", placeholder=True,
            member_count=0, review_count=0, distance=0, zone_id="",
        ),
        SimpleNamespace(
            id="host", label="192.0.2.10", kind="device", placeholder=False,
            member_count=0, review_count=0, distance=1, zone_id="",
        ),
    ]
    edges = [
        SimpleNamespace(
            id="edge-1", from_node_id="root", to_node_id="host",
            edge_type=edge_type, derived=derived, confidence=1.0,
        )
    ]
    return SimpleNamespace(nodes=nodes, edges=edges, not_shown=0, active_scans=0,
                           expanded_zone="", legend=())


def draw(snapshot_data: SimpleNamespace, state: render.ViewState) -> GridWindow:
    window = GridWindow()
    map_render.draw_map_panel(window, snapshot_data, state, {}, True, 0, 0, 20, 70)
    return window


class FlowDotTests(unittest.TestCase):
    def test_measured_link_carries_a_moving_dot(self) -> None:
        state = render.ViewState()
        state.animation = True
        positions = []
        for now in (0.0, 1.0, 2.0):
            state.now = now
            glyphs = draw(snapshot(), state).cells()
            dots = [cell for cell, char in glyphs.items()
                    if char == animation.FLOW_GLYPH]
            self.assertTrue(dots, f"no flow dot at t={now}")
            positions.append(set(dots))
        self.assertGreater(len({frozenset(item) for item in positions}), 1)

    def test_inferred_link_never_moves(self) -> None:
        state = render.ViewState()
        state.animation = True
        state.now = 1.0
        glyphs = draw(snapshot(edge_type="inferred", derived=True), state).cells()
        self.assertNotIn(animation.FLOW_GLYPH, glyphs.values())

    def test_animation_toggle_stills_the_map(self) -> None:
        state = render.ViewState()
        state.animation = False
        state.now = 1.0
        glyphs = draw(snapshot(), state).cells()
        self.assertNotIn(animation.FLOW_GLYPH, glyphs.values())


class RippleTests(unittest.TestCase):
    def test_new_node_ripples(self) -> None:
        state = render.ViewState()
        state.now = 10.0
        state.ripples = {"host": 9.75}
        glyphs = draw(snapshot(), state).cells()
        self.assertTrue(set(animation.RIPPLE_GLYPHS) & set(glyphs.values()))

    def test_finished_ripple_draws_nothing(self) -> None:
        state = render.ViewState()
        state.now = 10.0
        state.ripples = {"host": 8.0}
        glyphs = draw(snapshot(), state).cells()
        self.assertFalse(set(animation.RIPPLE_GLYPHS) & set(glyphs.values()))


class PulseStripTests(unittest.TestCase):
    def test_footer_draws_the_liveness_strip(self) -> None:
        window = GridWindow(12, 100)
        state = render.ViewState()
        state.pulse = [0, 1, 3, 9]
        render._draw_pulse(window, state, {}, 11, 100, 8, True)
        row = "".join(window.grid[11])
        self.assertTrue(row.rstrip(), "liveness strip not drawn")
        self.assertGreaterEqual(len(row.rstrip()), 90)
        self.assertIn(animation.PULSE_GLYPHS[-1], row)

    def test_strip_is_skipped_on_a_narrow_terminal(self) -> None:
        window = GridWindow(8, 40)
        state = render.ViewState()
        render._draw_pulse(window, state, {}, 7, 40, 2, True)
        self.assertEqual("".join(window.grid[7]).strip(), "")


class DiscoveryTrackingTests(unittest.TestCase):
    def test_first_snapshot_is_baseline_and_new_ids_ripple(self) -> None:
        from lumos.tui.app import _track_discovery, _sample_pulse

        state = render.ViewState()
        state.now = 100.0
        first = snapshot()
        _track_discovery(state, first)
        self.assertEqual(state.ripples, {}, "opening an engagement must not ripple")

        grown = snapshot()
        grown.nodes = first.nodes + [
            SimpleNamespace(
                id="new-host", label="192.0.2.11", kind="device", placeholder=False,
                member_count=0, review_count=0, distance=1, zone_id="",
            )
        ]
        _track_discovery(state, grown)
        self.assertIn("new-host", state.ripples)

        state.now = 200.0
        _track_discovery(state, grown)
        self.assertEqual(state.ripples, {}, "finished ripples are pruned")

    def test_pulse_samples_once_per_second(self) -> None:
        from lumos.tui.app import _sample_pulse

        state = render.ViewState()
        state.now = 10.0
        state.pulse_at = 10.0
        state.pulse_counter = 5
        _sample_pulse(state)
        self.assertEqual(state.pulse, [])
        state.now = 11.5
        state.pulse_counter = 9
        _sample_pulse(state)
        self.assertEqual(state.pulse, [9])

    def test_storm_limit_suppresses_ripples(self) -> None:
        from lumos.tui.app import _track_discovery

        state = render.ViewState()
        state.now = 5.0
        base = snapshot()
        _track_discovery(state, base)
        crowd = snapshot()
        crowd.nodes = base.nodes + [
            SimpleNamespace(
                id=f"n{index}", label=f"192.0.2.{index}", kind="device",
                placeholder=False, member_count=0, review_count=0,
                distance=1, zone_id="",
            )
            for index in range(animation.RIPPLE_STORM_LIMIT + 5)
        ]
        state.now = 6.0
        _track_discovery(state, crowd)
        self.assertEqual(state.ripples, {})


if __name__ == "__main__":
    unittest.main()