from __future__ import annotations

import gzip
import os
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from lumos.core.database import initialize_database, open_database
from lumos.core.nmap.runner import parse_manual_options
from lumos.core.scanning import ScopeConfirmationRequired, scan_database
from lumos.core.scope_store import add_scope_rule

ROOT = Path(__file__).resolve().parents[1]
FAKE = ROOT / "tests" / "fake_nmap" / "nmap"
FIXTURE = ROOT / "tests" / "fixtures" / "nmap" / "normal.xml"


class ScanningPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "engagement.sqlite"
        initialize_database(self.db, "test engagement")
        add_scope_rule(self.db, "lab", "192.0.2.0/24", included=True, author="tester")

    def test_fake_scan_streams_hosts_persists_provenance_and_compressed_xml(self) -> None:
        with patch.dict(os.environ, {"NMAP_FAKE_FIXTURE": str(FIXTURE)}):
            outcome = scan_database(
                self.db,
                "lab",
                ["192.0.2.10"],
                executable=str(FAKE),
                operator="tester",
            )
        self.assertEqual(outcome.result.exit_code, 0)
        self.assertEqual(outcome.result.hosts_seen, 1)
        conn = open_database(self.db, readonly=True)
        try:
            scan = conn.execute("SELECT status, exit_code, scope_override FROM scans").fetchone()
            self.assertEqual(tuple(scan), ("completed", 0, 0))
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM host_observations").fetchone()[0], 1)
            self.assertGreater(conn.execute("SELECT COUNT(*) FROM port_observations").fetchone()[0], 0)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0], 2)
            payload = conn.execute("SELECT payload, byte_length, sha256 FROM raw_scan_evidence").fetchone()
            self.assertEqual(gzip.decompress(payload[0]), FIXTURE.read_bytes())
            self.assertEqual(payload[1], len(FIXTURE.read_bytes()))
            self.assertEqual(payload[2], outcome.result.xml_sha256)
            self.assertGreater(conn.execute("SELECT COUNT(*) FROM topology_edges").fetchone()[0], 0)
            self.assertGreater(conn.execute("SELECT COUNT(*) FROM review_items").fetchone()[0], 0)
        finally:
            conn.close()

    def test_keyboard_interrupt_cancels_nmap_and_keeps_completed_host(self) -> None:
        original_join = threading.Thread.join
        interrupted = False

        def interrupt_after_output(thread, *args, **kwargs):
            nonlocal interrupted
            if thread.name == "lumos-nmap-reader" and not interrupted:
                interrupted = True
                time.sleep(0.5)  # Let the fake Nmap flush a complete fixture host, then interrupt the wait.
                raise KeyboardInterrupt
            return original_join(thread, *args, **kwargs)

        env = {
            "NMAP_FAKE_FIXTURE": str(FIXTURE),
            "NMAP_FAKE_HOLD_AFTER_OUTPUT": "10",
        }
        with patch.dict(os.environ, env), patch("threading.Thread.join", new=interrupt_after_output):
            outcome = scan_database(
                self.db,
                "lab",
                ["192.0.2.10"],
                executable=str(FAKE),
                operator="tester",
            )
        self.assertTrue(outcome.result.cancelled)
        self.assertEqual(outcome.result.hosts_seen, 1)
        conn = open_database(self.db, readonly=True)
        try:
            self.assertEqual(conn.execute("SELECT status FROM scans").fetchone()[0], "cancelled")
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM host_observations").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0], 2)
        finally:
            conn.close()

    def test_out_of_scope_traceroute_hop_is_flagged_without_blocking_scan(self) -> None:
        external_fixture = Path(self.tmp.name) / "external-hop.xml"
        xml = FIXTURE.read_text(encoding="utf-8").replace('ipaddr="192.0.2.1"', 'ipaddr="198.51.100.1"')
        external_fixture.write_text(xml, encoding="utf-8")
        with patch.dict(os.environ, {"NMAP_FAKE_FIXTURE": str(external_fixture)}):
            scan_database(self.db, "lab", ["192.0.2.10"], executable=str(FAKE), operator="tester")
        conn = open_database(self.db, readonly=True)
        try:
            row = conn.execute(
                "SELECT e.state FROM review_items r JOIN review_events e ON e.review_item_id = r.id "
                "WHERE r.reason_code = 'discovered_out_of_scope' ORDER BY e.created_at DESC LIMIT 1"
            ).fetchone()
            self.assertIsNotNone(row)
            self.assertEqual(row[0], "out_of_scope")
        finally:
            conn.close()

    def test_scope_guard_blocks_without_typed_confirmation(self) -> None:
        with patch.dict(os.environ, {"NMAP_FAKE_FIXTURE": str(FIXTURE)}):
            with self.assertRaises(ScopeConfirmationRequired) as caught:
                scan_database(self.db, "lab", ["203.0.113.4"], executable=str(FAKE))
        self.assertEqual(caught.exception.confirmation_text, "SCAN OUT OF SCOPE: 203.0.113.4")
        conn = open_database(self.db, readonly=True)
        try:
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 0)
        finally:
            conn.close()

    def test_scope_override_is_audited(self) -> None:
        with patch.dict(os.environ, {"NMAP_FAKE_FIXTURE": str(FIXTURE)}):
            outcome = scan_database(
                self.db,
                "lab",
                ["203.0.113.4"],
                executable=str(FAKE),
                scope_confirmation="SCAN OUT OF SCOPE: 203.0.113.4",
            )
        self.assertTrue(outcome.scope_override)
        conn = open_database(self.db, readonly=True)
        try:
            self.assertEqual(conn.execute("SELECT scope_override FROM scans").fetchone()[0], 1)
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM audit_events WHERE scope_override = 1").fetchone()[0], 2)
        finally:
            conn.close()

    def test_untrusted_manual_options_cannot_add_targets(self) -> None:
        with self.assertRaisesRegex(ValueError, "Unexpected positional token"):
            parse_manual_options("-p 22 203.0.113.4")


if __name__ == "__main__":
    unittest.main()
