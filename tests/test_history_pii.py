"""The history guard: the working tree is not the whole repository.

Skipped on a shallow clone, where older revisions genuinely are not present and
a clean result would be a false negative rather than a pass.
"""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "check_history_pii.py"


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO, capture_output=True, text=True, check=False
    ).stdout.strip()


@unittest.skipUnless((REPO / ".git").exists(), "not a git checkout")
class HistoryPiiTests(unittest.TestCase):
    def setUp(self) -> None:
        if _git("rev-parse", "--is-shallow-repository") == "true":
            self.skipTest("shallow clone: history is not all here")

    def test_the_committed_history_carries_no_personal_data(self) -> None:
        result = subprocess.run(
            ["python3", str(SCRIPT), "--repo", str(REPO)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("history clean", result.stdout)

    def test_the_guard_catches_a_leak_in_an_old_revision(self) -> None:
        """A guard that cannot fail on the leak it was written for is decoration."""
        tmp = REPO.parent / "lumos-history-guard-probe"
        subprocess.run(["rm", "-rf", str(tmp)], check=False)
        made = subprocess.run(["git", "init", "-q", str(tmp)], capture_output=True, check=False)
        if made.returncode != 0:  # pragma: no cover - environment without git
            self.skipTest("git init unavailable")
        # Split so this file never contains the leak it is testing for: the
        # guard would (correctly) flag its own test data.
        planted = "gateway " + "10." + "101.22.1 and " + "/home/" + "bit/tools\n"
        leak = tmp / "notes.md"
        leak.write_text(planted, encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp), "add", "."], check=False)
        subprocess.run(
            ["git", "-C", str(tmp), "-c", "user.name=t", "-c", "user.email=t@localhost",
             "commit", "-qm", "leak"],
            check=False,
        )
        leak.write_text("gateway 192.0.2.1 and /home/user/tools\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(tmp), "commit", "-qam", "clean"], check=False)
        result = subprocess.run(
            ["python3", str(SCRIPT), "--repo", str(tmp)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 1, "an old revision must still be caught")
        self.assertIn("10." + "101.22.1", result.stderr)
        self.assertIn("/home/" + "bit", result.stderr)
        subprocess.run(["rm", "-rf", str(tmp)], check=False)


if __name__ == "__main__":
    unittest.main()
