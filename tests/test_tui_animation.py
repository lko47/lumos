"""Animation is a pure function of the clock: dots, ripples, blink, pulse."""

from __future__ import annotations

import unittest

from lumos.tui import animation as anim


class FlowTests(unittest.TestCase):
    def test_dot_stays_on_the_segment_and_travels(self) -> None:
        start, end = (0, 0), (10, 0)
        first = anim.flow_position(start, end, 0.0, 0.0)
        later = anim.flow_position(start, end, 0.0, anim.FLOW_PERIOD_SECONDS / 2)
        self.assertEqual(first, (0, 0))
        self.assertEqual(later[1], 0)
        self.assertEqual(later[0], 5)
        for step in range(20):
            x, y = anim.flow_position(start, end, 0.1, step * 0.2)
            self.assertTrue(0 <= x <= 10 and 0 <= y <= 1)

    def test_phase_is_deterministic_and_spreads_edges(self) -> None:
        self.assertEqual(anim.phase_for("edge-1"), anim.phase_for("edge-1"))
        phases = {anim.phase_for(f"edge-{index}") for index in range(50)}
        self.assertGreater(len(phases), 40)
        self.assertTrue(all(0.0 <= value < 1.0 for value in phases))

    def test_wraparound_returns_to_the_start(self) -> None:
        start, end = (2, 3), (12, 9)
        once = anim.flow_position(start, end, 0.0, 0.0)
        again = anim.flow_position(start, end, 0.0, anim.FLOW_PERIOD_SECONDS)
        self.assertEqual(once, again)

    def test_short_links_are_not_animated(self) -> None:
        self.assertFalse(anim.flow_visible((4, 4), (4, 5), 0.0))
        self.assertTrue(anim.flow_visible((4, 4), (8, 4), 0.0))


class RippleTests(unittest.TestCase):
    def test_rings_expand_then_finish(self) -> None:
        started = 100.0
        radii = [
            anim.ripple_radius(started, started + offset)
            for offset in (0.0, 0.25, 0.45, 0.7)
        ]
        self.assertEqual(radii[:3], [0, 1, 2])
        self.assertEqual(radii[3], -1)

    def test_ring_cells_form_a_square(self) -> None:
        self.assertEqual(anim.ripple_cells((5, 5), -1), ())
        zero = anim.ripple_cells((5, 5), 0)
        self.assertEqual(zero, ((5, 5),) * 2)
        ring = anim.ripple_cells((5, 5), 2)
        self.assertIn((3, 5), ring)
        self.assertIn((7, 7), ring)
        self.assertNotIn((5, 5), ring)

    def test_glyphs_degrade_to_ascii(self) -> None:
        self.assertEqual(anim.ripple_glyph(0, unicode_ok=True), "▓")
        self.assertEqual(anim.ripple_glyph(0, unicode_ok=False), "#")

    def test_storm_threshold_caps_a_sweep(self) -> None:
        self.assertFalse(anim.storm(anim.RIPPLE_STORM_LIMIT))
        self.assertTrue(anim.storm(anim.RIPPLE_STORM_LIMIT + 1))

    def test_active_count_ignores_finished_ripples(self) -> None:
        ripples = [("a", 10.0), ("b", 10.1)]
        self.assertEqual(anim.active_ripples(ripples, 10.15), 2)
        self.assertEqual(anim.active_ripples(ripples, 12.0), 0)


class BlinkTests(unittest.TestCase):
    def test_blinks_then_settles(self) -> None:
        primed = 50.0
        cycle = anim.BLINK_ON_SECONDS + anim.BLINK_OFF_SECONDS
        self.assertTrue(anim.blink_visible(primed, primed))            # on
        self.assertFalse(anim.blink_visible(primed, primed + 0.7))      # off
        self.assertTrue(anim.blink_visible(primed, primed + cycle))     # on again
        settled = primed + cycle * anim.BLINK_CYCLES + 0.01
        self.assertTrue(anim.blink_visible(primed, settled))
        self.assertTrue(anim.blink_visible(primed, settled + 10.0))

    def test_clock_before_priming_is_still_solid(self) -> None:
        self.assertTrue(anim.blink_visible(10.0, 9.0))


class PulseTests(unittest.TestCase):
    def test_idle_line_still_marks_the_newest_second(self) -> None:
        row = anim.pulse_row([0] * 5, width=8)
        self.assertEqual(len(row), 8)
        self.assertEqual(row[:-1], anim.PULSE_GLYPHS[0] * 7)
        self.assertEqual(row[-1], anim.PULSE_GLYPHS[1], "idle tick must be visible")

    def test_busy_samples_rise(self) -> None:
        row = anim.pulse_row([0, 1, 4, 8], width=4)
        self.assertEqual(row[-1], anim.PULSE_GLYPHS[-1])
        self.assertEqual(row[0], anim.PULSE_GLYPHS[0])

    def test_ascii_fallback_uses_no_unicode(self) -> None:
        row = anim.pulse_row([0, 2, 8], width=3, ascii_ok=True)
        self.assertTrue(all(char in anim.PULSE_GLYPHS_ASCII for char in row))

    def test_tick_timeout_switches_with_activity(self) -> None:
        self.assertEqual(anim.tick_timeout(True), int(anim.TICK_SECONDS * 1000))
        self.assertEqual(anim.tick_timeout(False), int(anim.IDLE_SECONDS * 1000))


if __name__ == "__main__":
    unittest.main()
