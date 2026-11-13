"""External enumerators: no shell, scope first, missing binary is a sentence."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lumos.core import engine_scan, engines
from lumos.core.database import initialize_database
from lumos.core.scope_store import add_scope_rule

FAKE_DIR = Path(__file__).parent / "fake_masscan"


class EngineScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.database = self.root / "engine.sqlite"
        initialize_database(self.database, "engine test")
        add_scope_rule(self.database, "lab", "192.0.2.0/24", included=True)
        self.marker = self.root / "invoked"
        patcher = mock.patch.dict(
            os.environ,
            {"PATH": f"{FAKE_DIR}{os.pathsep}{os.environ.get('PATH', '')}",
             "FAKE_MASSCAN_MARKER": str(self.marker)},
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_masscan_xml_is_imported_and_recorded_as_masscan(self) -> None:
        scan_id, hosts, _message = engine_scan.scan_with_engine(
            self.database, "lab", "masscan", "192.0.2.40",
            engine_scan.EngineOptions(ports="22,443"),
        )
        self.assertTrue(scan_id)
        self.assertEqual(hosts, 1)
        self.assertTrue(self.marker.is_file(), "the engine must actually run")
        self.assertIn("--output-format xml", self.marker.read_text(encoding="utf-8"))

    def test_out_of_scope_target_never_reaches_the_binary(self) -> None:
        with self.assertRaises(engine_scan.EngineScanError):
            engine_scan.scan_with_engine(self.database, "lab", "masscan", "203.0.113.9")
        self.assertFalse(self.marker.exists(), "no packets for an out-of-scope target")

    def test_missing_binary_is_reported_not_raised_as_oserror(self) -> None:
        with mock.patch.object(engines, "which", return_value=None):
            with self.assertRaises(engine_scan.EngineScanError) as caught:
                engine_scan.scan_with_engine(self.database, "lab", "masscan", "192.0.2.40")
        self.assertIn("not installed", str(caught.exception))

    def test_naabu_is_refused_until_its_output_can_be_read(self) -> None:
        with mock.patch.object(engines, "which", return_value="/usr/bin/naabu"):
            with self.assertRaises(engine_scan.EngineScanError) as caught:
                engine_scan.scan_with_engine(self.database, "lab", "naabu", "192.0.2.40")
        self.assertIn("not imported yet", str(caught.exception))

    def test_argv_is_a_list_without_a_shell(self) -> None:
        engine = engines.by_name("masscan")
        argv = engine_scan.build_argv(
            engine, "/usr/bin/masscan", "192.0.2.40", "22", Path("/tmp/x.xml")
        )
        self.assertIsInstance(argv, list)
        self.assertEqual(argv[0], "/usr/bin/masscan")
        self.assertIn("--output-filename", argv)

    def test_engine_crash_without_output_is_an_error(self) -> None:
        with mock.patch.object(engine_scan, "run_engine", return_value=(2, "permission denied")):
            with self.assertRaises(engine_scan.EngineScanError) as caught:
                engine_scan.scan_with_engine(self.database, "lab", "masscan", "192.0.2.40")
        self.assertIn("no report", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
