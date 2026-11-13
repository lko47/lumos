"""Ping discovery and scope-checked target files."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lumos.core import scope
from lumos.core.nmap.runner import build_nmap_argv, parse_manual_options
from lumos.services.actions import SCAN_PRESETS


class TargetFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _file(self, text: str) -> Path:
        path = Path(self.tmp.name) / "targets.txt"
        path.write_text(text, encoding="utf-8")
        return path

    def test_comments_blanks_and_duplicates_are_handled(self) -> None:
        path = self._file("# lab\n192.0.2.10\n\n192.0.2.11  # the gateway\n192.0.2.10\n")
        self.assertEqual(
            scope.read_target_file(path), ("192.0.2.10", "192.0.2.11")
        )

    def test_commas_and_spaces_both_separate_targets(self) -> None:
        path = self._file("192.0.2.10, 192.0.2.11 192.0.2.12\n")
        self.assertEqual(len(scope.read_target_file(path)), 3)

    def test_a_missing_file_is_a_sentence_not_a_traceback(self) -> None:
        with self.assertRaises(scope.TargetFileError):
            scope.read_target_file(Path(self.tmp.name) / "nope.txt")

    def test_an_empty_file_is_refused(self) -> None:
        with self.assertRaises(scope.TargetFileError):
            scope.read_target_file(self._file("# nothing here\n"))

    def test_a_file_over_the_cap_is_refused(self) -> None:
        text = "\n".join(
            f"192.0.{index // 250}.{index % 250}" for index in range(5000)
        )
        with self.assertRaises(scope.TargetFileError):
            scope.read_target_file(self._file(text))


class DiscoveryScanTests(unittest.TestCase):
    def test_ping_discovery_argv_has_no_port_or_version_probe(self) -> None:
        argv = build_nmap_argv("nmap", ["192.0.2.10"], options=["-sn"])
        self.assertIn("-sn", argv)
        self.assertNotIn("-sV", argv)
        self.assertNotIn("-sT", argv)
        self.assertEqual(argv[-3:], ["-oX", "-", "192.0.2.10"])

    def test_discovery_is_accepted_as_a_scan_mode(self) -> None:
        self.assertEqual(parse_manual_options("-sn"), ["-sn"])

    def test_discovery_cannot_be_combined_with_port_scans(self) -> None:
        with self.assertRaises(ValueError):
            build_nmap_argv("nmap", ["192.0.2.10"], options=["-sn", "-sS"])

    def test_the_preset_is_offered(self) -> None:
        self.assertEqual(SCAN_PRESETS["discovery"], "-sn")


if __name__ == "__main__":
    unittest.main()
