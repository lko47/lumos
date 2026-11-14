"""The man page must not drift from the commands the program actually has."""

from __future__ import annotations

import shutil
import subprocess
import unittest
from pathlib import Path

from lumos import cli

MAN = Path(__file__).resolve().parents[1] / "docs" / "man" / "lumos.1"


class ManPageTests(unittest.TestCase):
    def test_every_command_is_documented(self) -> None:
        text = MAN.read_text(encoding="utf-8")
        missing = sorted(
            command for command in cli.SUBCOMMANDS if f"lumos {command}" not in text
        )
        self.assertEqual(missing, [], f"undocumented commands: {missing}")

    def test_the_page_renders_without_warnings(self) -> None:
        if shutil.which("groff") is None:
            self.skipTest("groff is not installed")
        result = subprocess.run(
            ["groff", "-man", "-Tutf8", "-P-cbou", "-ww", str(MAN)],
            capture_output=True, text=True, timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr.strip(), "")
        self.assertIn("LUMOS(1)", result.stdout)
        self.assertIn("EXIT STATUS", result.stdout)


if __name__ == "__main__":
    unittest.main()
