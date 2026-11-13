from __future__ import annotations

import gzip
import tempfile
import unittest
from pathlib import Path

from lumos.core.database import initialize_database, open_database
from lumos.core.scope_store import add_scope_rule
from lumos.core.xml_import import import_nmap_xml

ROOT = Path(__file__).resolve().parent
FIXTURES = ROOT / "fixtures" / "nmap"


class NmapXmlImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "import.sqlite"
        initialize_database(self.db, "XML import test")
        add_scope_rule(self.db, "lab", "192.0.2.0/24", included=True)

    def test_import_records_hosts_audit_and_compressed_original_xml(self) -> None:
        scan_id, hosts, error = import_nmap_xml(self.db, "lab", FIXTURES / "normal.xml")
        self.assertEqual(hosts, 1)
        self.assertEqual(error, "")
        conn = open_database(self.db, readonly=True)
        try:
            scan = conn.execute("SELECT nmap_version, status FROM scans WHERE id = ?", (scan_id,)).fetchone()
            self.assertEqual(tuple(scan), ("7.99", "completed"))
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM host_observations WHERE scan_id = ?", (scan_id,)).fetchone()[0], 1)
            events = [row[0] for row in conn.execute("SELECT event_type FROM audit_events WHERE scan_id = ? ORDER BY occurred_at", (scan_id,))]
            self.assertEqual(events, ["xml_import_started", "xml_import_finished"])
            evidence = conn.execute("SELECT payload, byte_length FROM raw_scan_evidence WHERE scan_id = ?", (scan_id,)).fetchone()
            self.assertEqual(gzip.decompress(evidence[0]), (FIXTURES / "normal.xml").read_bytes())
            self.assertEqual(evidence[1], (FIXTURES / "normal.xml").stat().st_size)
        finally:
            conn.close()

    def test_hostile_dtd_is_rejected_before_creating_scan(self) -> None:
        from lumos.core.nmap.xml_stream import NmapXmlError

        with self.assertRaises(NmapXmlError):
            import_nmap_xml(self.db, "lab", FIXTURES / "hostile-dtd.xml")
        conn = open_database(self.db, readonly=True)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 0)
        finally:
            conn.close()

    def test_nmap_xml_file_imports_end_to_end(self) -> None:
        scan_id, hosts, error = import_nmap_xml(self.db, "lab", FIXTURES / "connect-scan.xml")
        self.assertEqual((hosts, error), (1, ""))
        conn = open_database(self.db, readonly=True)
        try:
            scan = conn.execute("SELECT status, nmap_version FROM scans WHERE id = ?", (scan_id,)).fetchone()
            self.assertEqual(tuple(scan), ("completed", "7.993"))
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM host_observations").fetchone()[0], 1)
            ports = {
                (row[0], row[1])
                for row in conn.execute("SELECT port, state FROM port_observations")
            }
            self.assertIn((22, "open"), ports)
            self.assertIn((80, "closed"), ports)
        finally:
            conn.close()

    def test_truncated_import_keeps_scan_failed_and_reports_partial_status(self) -> None:
        scan_id, hosts, error = import_nmap_xml(self.db, "lab", FIXTURES / "truncated.xml")
        self.assertEqual(hosts, 0)
        self.assertTrue(error)
        conn = open_database(self.db, readonly=True)
        try:
            self.assertEqual(conn.execute("SELECT status FROM scans WHERE id = ?", (scan_id,)).fetchone()[0], "failed")
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit_events WHERE scan_id = ?", (scan_id,)).fetchone()[0], 2)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
