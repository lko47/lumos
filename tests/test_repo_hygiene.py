"""No engagement database, scan export or report may ever be committed.

The repository is public. These checks run in CI, so a `git add -A` in a
directory where Lumos wrote an engagement file fails the suite instead of
publishing scan data.
"""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SQLITE_MAGIC = b"SQLite format 3\x00"
LUMOS_APPLICATION_ID = 0x4C554D53  # "LUMS", at byte offset 68 of an engagement file
APPLICATION_ID_OFFSET = 68
SUSPICIOUS_SUFFIXES = {
    ".sqlite", ".sqlite3", ".db", ".sqlite-wal", ".sqlite-shm", ".sqlite-journal",
    ".nmap", ".gnmap", ".xml", ".xml.gz", ".nmap.gz", ".zip",
}
# Nmap XML is only allowed where it is a test fixture or a hostile-input probe.
XML_ALLOWED_PREFIXES = ("tests/fixtures/", "scripts/review/")
REQUIRED_IGNORE_PATTERNS = (
    "*.sqlite",
    "*.sqlite-wal",
    "*.sqlite-journal",
    "*.db",
    "*.nmap",
    "*.gnmap",
    "*.xml",
    "engagements/",
    "/reports/",
)


def tracked_files() -> list[str]:
    result = subprocess.run(
        ["git", "ls-files", "-z"], cwd=ROOT, capture_output=True, check=False
    )
    if result.returncode != 0:
        raise unittest.SkipTest("git is not available")
    return [name for name in result.stdout.decode("utf-8", "replace").split("\0") if name]


def is_engagement_database(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            header = handle.read(APPLICATION_ID_OFFSET + 4)
    except OSError:
        return False
    if not header.startswith(SQLITE_MAGIC):
        return False
    if len(header) < APPLICATION_ID_OFFSET + 4:
        return True
    application_id = int.from_bytes(header[APPLICATION_ID_OFFSET:APPLICATION_ID_OFFSET + 4], "big")
    return application_id == LUMOS_APPLICATION_ID


class RepositoryHygieneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.files = tracked_files()

    def test_no_engagement_database_is_tracked(self) -> None:
        offenders = [
            name for name in self.files
            if (ROOT / name).is_file() and is_engagement_database(ROOT / name)
        ]
        self.assertEqual(offenders, [], "engagement database committed to a public repo")

    def test_sqlite_header_detection_works(self) -> None:
        """Guard the guard: a real engagement file must be recognised."""
        with self.subTest("synthetic header"):
            import tempfile

            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "fake.sqlite"
                header = SQLITE_MAGIC + b"\x00" * (APPLICATION_ID_OFFSET - len(SQLITE_MAGIC))
                path.write_bytes(header + LUMOS_APPLICATION_ID.to_bytes(4, "big"))
                self.assertTrue(is_engagement_database(path))

    def test_no_scan_export_or_report_is_tracked(self) -> None:
        offenders = []
        for name in self.files:
            suffix = "".join(Path(name).suffixes[-1:])
            if suffix not in SUSPICIOUS_SUFFIXES:
                continue
            if suffix == ".xml" and name.startswith(XML_ALLOWED_PREFIXES):
                continue
            offenders.append(name)
        self.assertEqual(offenders, [], "scan artifact committed: move it out of the repo")

    def test_gitignore_covers_engagement_output(self) -> None:
        ignore = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        entries = {line.strip() for line in ignore}
        missing = [pattern for pattern in REQUIRED_IGNORE_PATTERNS if pattern not in entries]
        self.assertEqual(missing, [], "gitignore lost an engagement pattern")

    def test_ignored_engagement_file_is_not_staged(self) -> None:
        """An engagement file written inside the tree must stay untracked."""
        candidate = ROOT / "engagements" / "hygiene-probe.sqlite"
        candidate.parent.mkdir(exist_ok=True)
        candidate.write_bytes(SQLITE_MAGIC + b"\x00" * 120)
        try:
            result = subprocess.run(
                ["git", "check-ignore", "-v", str(candidate)],
                cwd=ROOT, capture_output=True, text=True, check=False,
            )
            self.assertEqual(result.returncode, 0, "engagement file inside the repo is not ignored")
        finally:
            candidate.unlink(missing_ok=True)
            try:
                candidate.parent.rmdir()
            except OSError:
                pass


if __name__ == "__main__":
    unittest.main()