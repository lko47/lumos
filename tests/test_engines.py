"""Engine detection and the settings model: facts, never guesses."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lumos.core import engines


class DetectTests(unittest.TestCase):
    def test_shell_is_never_used(self) -> None:
        source = Path(engines.__file__).read_text(encoding="utf-8")
        self.assertNotIn("shell=True", source)
        self.assertNotIn("os.system", source)

    def test_missing_binary_reports_none(self) -> None:
        with mock.patch.object(engines.shutil, "which", return_value=None):
            self.assertEqual(engines.detect(), {engine.name: None for engine in engines.ENGINES})

    def test_argv_is_a_list_and_never_a_string(self) -> None:
        for engine in engines.ENGINES:
            argv = engine.argv("192.0.2.10", "22,80")
            self.assertIsInstance(argv, list)
            self.assertIn("192.0.2.10", argv)

    def test_unknown_engine_is_not_fatal(self) -> None:
        self.assertIsNone(engines.by_name("nope"))


class SettingsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "settings.json"

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_only_installed_engines_are_selectable(self) -> None:
        found = {"nmap": "/usr/bin/nmap", "masscan": None, "naabu": "/usr/bin/naabu",
                 "rustscan": None}
        with mock.patch.object(engines, "detect", return_value=found):
            rows = engines.statuses(self.path)
        by_name = {row.name: row for row in rows}
        self.assertTrue(by_name["nmap"].installed)
        self.assertFalse(by_name["masscan"].installed)
        self.assertEqual(by_name["masscan"].checkbox(), "[ ]")

    def test_toggle_writes_the_file_and_survives_a_reload(self) -> None:
        found = {"nmap": "/usr/bin/nmap", "masscan": None, "naabu": None, "rustscan": None}
        with mock.patch.object(engines, "detect", return_value=found), \
                mock.patch.object(engines, "which", return_value="/usr/bin/nmap"):
            rows = engines.toggle("nmap", self.path)
            self.assertFalse({row.name for row in rows if row.enabled})
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            self.assertEqual(payload["enabled_engines"], [])
            rows = engines.toggle("nmap", self.path)
            self.assertTrue({row.name for row in rows if row.enabled})

    def test_toggle_refuses_an_absent_binary(self) -> None:
        with mock.patch.object(engines, "detect", return_value={name: None for name in
                                                                ("nmap", "masscan", "naabu", "rustscan")}), \
                mock.patch.object(engines, "which", return_value=None):
            rows = engines.toggle("masscan", self.path)
        self.assertFalse(any(row.enabled for row in rows))

    def test_broken_settings_file_does_not_stop_an_assessment(self) -> None:
        self.path.write_text("{not json", encoding="utf-8")
        with mock.patch.object(engines, "detect", return_value={"nmap": "/usr/bin/nmap"}):
            self.assertEqual(engines.load_enabled(self.path), frozenset({"nmap"}))


if __name__ == "__main__":
    unittest.main()
