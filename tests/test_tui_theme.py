from __future__ import annotations

import os
import unittest
from unittest.mock import patch

from lumos.tui import theme


class ThemeResolutionTests(unittest.TestCase):
    def test_256_colour_uses_palette_indices(self) -> None:
        resolved = theme.resolved_styles("aurora", theme.CAPABILITY_256)
        self.assertEqual(resolved["edge_traceroute"][0], 39)

    def test_16_colour_never_emits_a_256_index(self) -> None:
        for name in theme.THEMES:
            resolved = theme.resolved_styles(name, theme.CAPABILITY_16)
            for style_name, (fg, bg, _attr) in resolved.items():
                with self.subTest(theme=name, style=style_name):
                    self.assertLess(fg, 16)
                    self.assertLess(bg, 16)

    def test_monochrome_drops_every_colour(self) -> None:
        resolved = theme.resolved_styles("matrix", theme.CAPABILITY_MONO)
        self.assertTrue(all(fg == -1 and bg == -1 for fg, bg, _attr in resolved.values()))
        # Hierarchy must survive through weights and inversion.
        self.assertNotEqual(resolved["selected"][2], 0)
        self.assertNotEqual(resolved["brand"][2], 0)

    def test_every_theme_defines_the_same_semantic_styles(self) -> None:
        reference = set(theme.THEMES["aurora"])
        for name, palette in theme.THEMES.items():
            with self.subTest(theme=name):
                self.assertEqual(set(palette), reference)

    def test_required_styles_exist(self) -> None:
        required = {
            "brand", "subtitle", "accent", "muted", "title", "border", "border_focus",
            "selected", "tab", "tab_active", "root", "device", "hop", "unknown_hop",
            "manual", "zone", "scan_running", "scan_completed", "scan_failed",
            "scan_cancelled", "scan_queued", "help_key", "help_text", "palette_selected",
            "port_open", "ok", "warn", "error",
        }
        self.assertLessEqual(required, set(theme.THEMES["aurora"]))

    def test_next_theme_cycles_without_selecting_mono(self) -> None:
        seen = []
        current = theme.THEME_ORDER[0]
        for _ in range(len(theme.THEME_ORDER)):
            current = theme.next_theme(current)
            seen.append(current)
        # Each call advances by one and wraps; mono is reachable only via NO_COLOR.
        self.assertEqual(seen, list(theme.THEME_ORDER[1:]) + [theme.THEME_ORDER[0]])
        self.assertNotIn("mono", seen)
        self.assertEqual(theme.next_theme("unknown"), theme.THEME_ORDER[0])

    def test_no_color_forces_monochrome_capability(self) -> None:
        with patch.dict(os.environ, {"NO_COLOR": "1"}):
            self.assertEqual(theme.detect_capability(), theme.CAPABILITY_MONO)


if __name__ == "__main__":
    unittest.main()
