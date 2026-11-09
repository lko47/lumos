from __future__ import annotations

import unittest

from lumos.tui.braille import BrailleCanvas


class BrailleCanvasTests(unittest.TestCase):
    def test_dot_mapping_matches_unicode_braille_bit_order(self) -> None:
        expected = {
            (0, 0): 0x01,
            (1, 0): 0x08,
            (0, 1): 0x02,
            (1, 1): 0x10,
            (0, 2): 0x04,
            (1, 2): 0x20,
            (0, 3): 0x40,
            (1, 3): 0x80,
        }
        for (x, y), mask in expected.items():
            with self.subTest(dot=(x, y)):
                canvas = BrailleCanvas(1, 1)
                canvas.set_dot(x, y)
                self.assertEqual(ord(canvas.render()[0][0]) - 0x2800, mask)

    def test_horizontal_line_renders_across_braille_cells(self) -> None:
        canvas = BrailleCanvas(2, 1)
        canvas.draw_line((0, 0), (3, 0))
        rendered = canvas.render()
        self.assertEqual(len(rendered), 1)
        self.assertEqual(len(rendered[0]), 2)
        self.assertTrue(all(ord(character) > 0x2800 for character in rendered[0]))

    def test_vertical_line_uses_all_four_dot_rows(self) -> None:
        canvas = BrailleCanvas(1, 1)
        canvas.draw_line((0, 0), (0, 3))
        self.assertEqual(ord(canvas.render()[0][0]) - 0x2800, 0x47)

    def test_diagonal_line_is_clipped_to_canvas(self) -> None:
        canvas = BrailleCanvas(2, 2)
        canvas.draw_line((-2, -2), (5, 5))
        rendered = canvas.render()
        self.assertEqual((len(rendered), len(rendered[0])), (2, 2))
        self.assertTrue(any(character != "\u2800" for row in rendered for character in row))

    def test_edge_styles_distinguish_alternate_and_inferred_paths(self) -> None:
        solid = BrailleCanvas(4, 2)
        alternate = BrailleCanvas(4, 2)
        inferred = BrailleCanvas(4, 2)
        solid.draw_line((0, 3), (7, 3), style="traceroute")
        alternate.draw_line((0, 3), (7, 3), style="alternate")
        inferred.draw_line((0, 3), (7, 3), style="inferred")
        self.assertNotEqual(solid.render(), alternate.render())
        self.assertNotEqual(solid.render(), inferred.render())
        self.assertNotEqual(alternate.render(), inferred.render())

    def test_invalid_dimensions_are_rejected(self) -> None:
        with self.assertRaises(ValueError):
            BrailleCanvas(-1, 1)
        with self.assertRaises(ValueError):
            BrailleCanvas(1, -1)


if __name__ == "__main__":
    unittest.main()
