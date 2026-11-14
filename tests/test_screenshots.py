"""Screenshots are generated from demo data, and must stay that way.

A screenshot is the easiest place to leak a real network: it is an image, so no
lint looks at it and nobody diffs it. These tests treat the committed SVGs like
any other text artefact.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

SHOTS = Path(__file__).resolve().parents[1] / "docs" / "screenshots"
PRIVATE = re.compile(
    r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|127\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|169\.254\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3}|fe80::)\b"
)
ALLOWED = re.compile(r"\b(?:192\.0\.2|198\.51\.100|203\.0\.113|198\.18)\.")


class ScreenshotTests(unittest.TestCase):
    def test_the_committed_screenshots_exist_and_are_vector(self) -> None:
        files = sorted(SHOTS.glob("*.svg"))
        self.assertGreaterEqual(len(files), 2, "the README refers to two screenshots")
        for path in files:
            text = path.read_text(encoding="utf-8")
            self.assertTrue(text.startswith("<svg"), f"{path.name} is not an SVG")
            self.assertGreater(len(text), 2000, f"{path.name} looks empty")
            self.assertIn("demo", text.lower(), f"{path.name} is not from the demo engagement")

    def test_no_screenshot_contains_a_real_looking_network(self) -> None:
        for path in sorted(SHOTS.glob("*.svg")):
            text = path.read_text(encoding="utf-8")
            for match in PRIVATE.finditer(text):
                self.assertIsNone(
                    ALLOWED.match(match.group(0) + "."), f"{path.name}: {match.group(0)}"
                )
            self.assertNotIn("/home/", text, f"{path.name} contains a home path")

    def test_the_generator_never_opens_a_stored_engagement(self) -> None:
        script = (SHOTS.parents[1] / "scripts" / "make_screenshot.py").read_text(encoding="utf-8")
        self.assertIn("tempfile.TemporaryDirectory", script)
        self.assertIn("demo", script)


if __name__ == "__main__":
    unittest.main()
