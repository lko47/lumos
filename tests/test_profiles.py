"""Scan profiles as data: additive, quoted safely, and unable to smuggle flags."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lumos.services import actions, profiles


class ProfileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "profiles.json"

    def _write(self, payload: object) -> Path:
        self.path.write_text(json.dumps(payload), encoding="utf-8")
        return self.path

    def test_the_built_ins_work_with_no_file_at_all(self) -> None:
        with mock.patch.dict(os.environ, {"LUMOS_PROFILES": str(self.path)}):
            self.assertEqual(profiles.load_profiles(), {})
            self.assertEqual(
                profiles.options_for(actions.SCAN_PRESETS, "service"),
                actions.SCAN_PRESETS["service"],
            )

    def test_custom_profiles_are_added_after_the_built_ins(self) -> None:
        self._write({"profiles": {"quick-web": {"options": "-sT -p 80,443"}}})
        with mock.patch.dict(os.environ, {"LUMOS_PROFILES": str(self.path)}):
            self.assertEqual(profiles.choices(actions.SCAN_PRESETS)[-1], "quick-web")
            self.assertEqual(
                profiles.options_for(actions.SCAN_PRESETS, "quick-web"), "-sT -p 80,443"
            )

    def test_a_profile_cannot_redefine_a_built_in(self) -> None:
        self._write({"profiles": {"service": "-sT"}})
        with mock.patch.dict(os.environ, {"LUMOS_PROFILES": str(self.path)}):
            with self.assertRaises(profiles.ProfileError):
                profiles.options_for(actions.SCAN_PRESETS, "service")

    def test_flags_that_write_or_read_behind_the_guard_are_refused(self) -> None:
        for options in ("-oX out.xml -sT", "-iL targets.txt", "--script vuln"):
            self._write({"profiles": {"sneaky": options}})
            with mock.patch.dict(os.environ, {"LUMOS_PROFILES": str(self.path)}):
                with self.assertRaises(profiles.ProfileError, msg=options):
                    profiles.load_profiles()

    def test_quoting_is_parsed_and_normalised(self) -> None:
        self._write({"profiles": {"quoted": {"options": '-sT   -p "80,443"'}}})
        with mock.patch.dict(os.environ, {"LUMOS_PROFILES": str(self.path)}):
            self.assertEqual(profiles.load_profiles()["quoted"].options, "-sT -p 80,443")

    def test_broken_json_and_unbalanced_quotes_are_reported_not_ignored(self) -> None:
        self.path.write_text("{not json", encoding="utf-8")
        with mock.patch.dict(os.environ, {"LUMOS_PROFILES": str(self.path)}):
            with self.assertRaises(profiles.ProfileError):
                profiles.load_profiles()
        self._write({"profiles": {"bad": {"options": '-sT -p "80'}}})
        with mock.patch.dict(os.environ, {"LUMOS_PROFILES": str(self.path)}):
            with self.assertRaises(profiles.ProfileError):
                profiles.load_profiles()

    def test_an_unknown_profile_is_an_error_not_an_empty_scan(self) -> None:
        with mock.patch.dict(os.environ, {"LUMOS_PROFILES": str(self.path)}):
            with self.assertRaises(profiles.ProfileError):
                profiles.options_for(actions.SCAN_PRESETS, "no-such-profile")


if __name__ == "__main__":
    unittest.main()
