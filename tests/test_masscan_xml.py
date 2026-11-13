"""A masscan report is Nmap-shaped: it must import through the same path."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lumos.core.database import initialize_database
from lumos.core.scope_store import add_scope_rule
from lumos.core.xml_import import import_nmap_xml

FIXTURE = Path(__file__).parent / "fixtures" / "nmap" / "masscan.xml"


class MasscanImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.database = Path(self.tmp.name) / "masscan.sqlite"
        initialize_database(self.database, "masscan test")
        add_scope_rule(self.database, "lab", "192.0.2.0/24", included=True)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_ports_and_hosts_are_imported(self) -> None:
        scan_id, hosts, _sha = import_nmap_xml(self.database, "lab", FIXTURE)
        self.assertTrue(scan_id)
        self.assertEqual(hosts, 2)
        with sqlite3.connect(self.database) as connection:
            ports = connection.execute(
                "SELECT COUNT(*) FROM port_observations WHERE state = 'open'"
            ).fetchone()[0]
            version, args = connection.execute(
                "SELECT nmap_version, redacted_args_json FROM scans WHERE id = ?", (scan_id,)
            ).fetchone()
        self.assertEqual(ports, 3)
        self.assertEqual(version, "1.3.2", "masscan's version is recorded as the probe version")
        self.assertIn("masscan", args.lower() + str(args), "the tool that produced it is recorded")


if __name__ == "__main__":
    unittest.main()
