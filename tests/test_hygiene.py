"""Repository hygiene rules that are easy to lose in an edit (F7)."""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class IgnoreRulesTests(unittest.TestCase):
    def patterns(self) -> set[str]:
        text = (ROOT / ".gitignore").read_text(encoding="utf-8")
        return {
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        }

    def test_build_output_is_ignored(self) -> None:
        # `.build/` does not cover `pipx install .` / `python -m build` output in build/.
        self.assertIn("build/", self.patterns())

    def test_engagement_artifacts_are_ignored(self) -> None:
        patterns = self.patterns()
        for pattern in ("*.sqlite", "*.sqlite-wal", "*.sqlite-shm", "*.db", "*.xml"):
            self.assertIn(pattern, patterns)
        self.assertIn("!tests/fixtures/nmap/*.xml", patterns)

    def test_no_engagement_artifact_is_tracked(self) -> None:
        tracked = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files"],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.splitlines()
        offenders = [
            path
            for path in tracked
            if path.endswith((".sqlite", ".sqlite-wal", ".sqlite-shm", ".db"))
        ]
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
