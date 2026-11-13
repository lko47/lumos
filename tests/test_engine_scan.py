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
BIN_DIR = Path(__file__).parent / "fake_engines"


class EngineScanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.path_dirs = f"{BIN_DIR}{os.pathsep}{FAKE_DIR}"
        self.database = self.root / "engine.sqlite"
        initialize_database(self.database, "engine test")
        add_scope_rule(self.database, "lab", "192.0.2.0/24", included=True)
        self.marker = self.root / "invoked"
        patcher = mock.patch.dict(
            os.environ,
            {"PATH": f"{self.path_dirs}{os.pathsep}{os.environ.get('PATH', '')}",
             "FAKE_MASSCAN_MARKER": str(self.marker)},
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        enabled = mock.patch.object(engines, "load_enabled", return_value=frozenset(
            {"nmap", "masscan", "naabu", "rustscan"}))
        enabled.start()
        self.addCleanup(enabled.stop)

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

    def test_an_engine_without_an_importer_is_refused(self) -> None:
        with mock.patch.object(engines, "which", return_value="/usr/bin/nmap"):
            with self.assertRaises(engine_scan.EngineScanError) as caught:
                engine_scan.scan_with_engine(self.database, "lab", "nmap", "192.0.2.40")
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


class CommandLineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.database = Path(self.tmp.name) / "cli.sqlite"
        initialize_database(self.database, "cli test")
        add_scope_rule(self.database, "lab", "192.0.2.0/24", included=True)
        patcher = mock.patch.dict(
            os.environ, {"PATH": f"{FAKE_DIR}{os.pathsep}{os.environ.get('PATH', '')}"}
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def _args(self, target: str):
        import argparse

        return argparse.Namespace(
            database=self.database, network="lab", engine="masscan", targets=[target],
            engine_ports="22,443", engine_rate=500, operator="tester",
        )

    def test_engine_scan_command_reports_each_target(self) -> None:
        from lumos import cli

        self.assertEqual(cli._run_engine_scan(self._args("192.0.2.40")), 0)

    def test_engine_scan_command_fails_outside_scope(self) -> None:
        from lumos import cli

        self.assertEqual(cli._run_engine_scan(self._args("203.0.113.5")), 1)


class JsonAndGreppableEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.database = Path(self.tmp.name) / "engines.sqlite"
        initialize_database(self.database, "engines")
        add_scope_rule(self.database, "lab", "192.0.2.0/24", included=True)
        patcher = mock.patch.dict(
            os.environ,
            {"PATH": f"{BIN_DIR}{os.pathsep}{FAKE_DIR}{os.pathsep}{os.environ.get('PATH', '')}"},
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        enabled = mock.patch.object(engines, "load_enabled", return_value=frozenset(
            {"nmap", "masscan", "naabu", "rustscan"}))
        enabled.start()
        self.addCleanup(enabled.stop)

    def _ports(self) -> list[int]:
        import sqlite3

        with sqlite3.connect(self.database) as connection:
            rows = connection.execute(
                "SELECT port FROM port_observations WHERE state = 'open' ORDER BY port"
            ).fetchall()
        return [row[0] for row in rows]

    def test_naabu_json_lines_become_observations(self) -> None:
        _scan_id, hosts, _message = engine_scan.scan_with_engine(
            self.database, "lab", "naabu", "192.0.2.50"
        )
        self.assertEqual(hosts, 1)
        self.assertEqual(self._ports(), [22, 8080])

    def test_naabu_garbage_lines_are_ignored(self) -> None:
        records = engine_scan.naabu_records(
            '{"ip":"192.0.2.50","port":22}\nnot json\n{"ip":"192.0.2.50","port":"x"}'
        )
        self.assertEqual(records, [{"address": "192.0.2.50", "port": 22, "protocol": "tcp"}])

    def test_rustscan_greppable_lines_become_observations(self) -> None:
        _scan_id, hosts, _message = engine_scan.scan_with_engine(
            self.database, "lab", "rustscan", "192.0.2.60"
        )
        self.assertEqual(hosts, 2)
        self.assertEqual(self._ports(), [22, 443, 8080])

    def test_empty_discovery_is_an_error_not_an_empty_scan(self) -> None:
        with mock.patch.object(engine_scan, "run_engine_capture", return_value=(0, "", "")):
            with self.assertRaises(engine_scan.EngineScanError) as caught:
                engine_scan.scan_with_engine(self.database, "lab", "naabu", "192.0.2.50")
        self.assertIn("found no open ports", str(caught.exception))

    def test_the_tool_that_produced_the_ports_is_recorded(self) -> None:
        import sqlite3

        scan_id, _hosts, _message = engine_scan.scan_with_engine(
            self.database, "lab", "naabu", "192.0.2.50"
        )
        with sqlite3.connect(self.database) as connection:
            args = connection.execute(
                "SELECT redacted_args_json FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()[0]
        self.assertIn("naabu", args)


class SettingsGateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.database = Path(self.tmp.name) / "gate.sqlite"
        initialize_database(self.database, "gate")
        add_scope_rule(self.database, "lab", "192.0.2.0/24", included=True)
        patcher = mock.patch.dict(
            os.environ,
            {"PATH": f"{BIN_DIR}{os.pathsep}{FAKE_DIR}{os.pathsep}{os.environ.get('PATH', '')}"},
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_an_engine_switched_off_in_settings_is_refused(self) -> None:
        gone = mock.patch.object(engines, "load_enabled", return_value=frozenset({"nmap"}))
        gone.start()
        self.addCleanup(gone.stop)
        with self.assertRaises(engine_scan.EngineScanError) as caught:
            engine_scan.scan_with_engine(self.database, "lab", "masscan", "192.0.2.40")
        self.assertIn("switched off", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
