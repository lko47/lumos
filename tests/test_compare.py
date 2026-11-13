"""Comparing two scans says what appeared, went away or changed."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lumos.core.database import initialize_database, open_database
from lumos.services import compare


SCHEMA_VANTAGE = """
INSERT INTO vantage_points (id, engagement_id, scanner_name, operator, created_at)
VALUES ('vantage-1', ?, 'scanner-host', 'tester', '2026-01-01T00:00:00Z')
"""

SCHEMA_NETWORK = """
INSERT INTO networks (id, engagement_id, name, cidr, created_at)
VALUES ('net-1', ?, 'lab', '192.0.2.0/24', '2026-01-01T00:00:00Z')
"""


class CompareTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "compare.sqlite"
        initialize_database(self.db, "compare")
        conn = open_database(self.db)
        with conn:
            engagement = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()[0]
            conn.execute(SCHEMA_VANTAGE, (engagement,))
            conn.execute(SCHEMA_NETWORK, (engagement,))
        conn.close()
        self.engagement = engagement

    def _scan(self, scan_id: str, started: str, hosts: dict[str, list[tuple[int, str, str]]]) -> None:
        conn = open_database(self.db)
        with conn:
            conn.execute(
                "INSERT INTO scans (id, engagement_id, vantage_point_id, exact_args_json,"
                " redacted_args_json, targets_json, started_at, ended_at, status)"
                " VALUES (?, ?, 'vantage-1', '[]', '[]', '[\"192.0.2.0/24\"]', ?, ?, 'completed')",
                (scan_id, self.engagement, started, started),
            )
            for index, (address, ports) in enumerate(sorted(hosts.items())):
                device_id = f"{scan_id}-dev-{index}"
                host_id = f"{scan_id}-host-{index}"
                address_id = f"addr-{address}"
                conn.execute(
                    "INSERT OR IGNORE INTO addresses (id, network_id, kind, normalized_value,"
                    " display_value, created_at) VALUES (?, 'net-1', 'ipv4', ?, ?, ?)",
                    (address_id, address, address, started),
                )
                conn.execute(
                    "INSERT INTO devices (id, engagement_id, created_at) VALUES (?, ?, ?)",
                    (device_id, self.engagement, started),
                )
                conn.execute(
                    "INSERT INTO host_observations (id, scan_id, device_id, observed_at)"
                    " VALUES (?, ?, ?, ?)",
                    (host_id, scan_id, device_id, started),
                )
                conn.execute(
                    "INSERT INTO observation_addresses (host_observation_id, address_id)"
                    " VALUES (?, ?)",
                    (host_id, address_id),
                )
                for port, state, service in ports:
                    conn.execute(
                        "INSERT INTO port_observations (id, host_observation_id, protocol,"
                        " port, state, service) VALUES (?, ?, 'tcp', ?, ?, ?)",
                        (f"{host_id}-{port}", host_id, port, state, service),
                    )
        conn.close()

    def test_a_new_host_and_a_new_port_both_show_up(self) -> None:
        self._scan("aaa", "2026-01-01T00:00:00Z", {"192.0.2.10": [(22, "open", "ssh")]})
        self._scan("bbb", "2026-01-02T00:00:00Z", {
            "192.0.2.10": [(22, "open", "ssh"), (443, "open", "https")],
            "192.0.2.11": [(80, "open", "http")],
        })
        diff = compare.diff_scans(self.db, "aaa", "bbb")
        self.assertEqual([h.address for h in diff.by_status(compare.ADDED)], ["192.0.2.11"])
        changed = diff.by_status(compare.CHANGED)[0]
        self.assertEqual(changed.address, "192.0.2.10")
        self.assertEqual([line.port for line in changed.ports_added], [443])

    def test_a_host_that_disappeared_is_reported_as_gone(self) -> None:
        self._scan("aaa", "2026-01-01T00:00:00Z", {
            "192.0.2.10": [(22, "open", "ssh")],
            "192.0.2.20": [(8080, "open", "http-alt")],
        })
        self._scan("bbb", "2026-01-02T00:00:00Z", {"192.0.2.10": [(22, "open", "ssh")]})
        diff = compare.diff_scans(self.db, "aaa", "bbb")
        self.assertEqual([h.address for h in diff.by_status(compare.REMOVED)], ["192.0.2.20"])

    def test_a_service_change_counts_as_changed(self) -> None:
        self._scan("aaa", "2026-01-01T00:00:00Z", {"192.0.2.10": [(443, "open", "ssl/http")]})
        self._scan("bbb", "2026-01-02T00:00:00Z", {"192.0.2.10": [(443, "open", "https")]})
        diff = compare.diff_scans(self.db, "aaa", "bbb")
        changed = diff.by_status(compare.CHANGED)[0]
        self.assertEqual(changed.ports_changed[0][0].service, "ssl/http")
        self.assertEqual(changed.ports_changed[0][1].service, "https")

    def test_identical_scans_report_no_difference(self) -> None:
        same = {"192.0.2.10": [(22, "open", "ssh")]}
        self._scan("aaa", "2026-01-01T00:00:00Z", same)
        self._scan("bbb", "2026-01-02T00:00:00Z", same)
        diff = compare.diff_scans(self.db, "aaa", "bbb")
        self.assertEqual(diff.by_status(compare.CHANGED), ())
        self.assertIn("no differences", compare.render_text(diff))

    def test_a_scan_cannot_be_compared_with_itself(self) -> None:
        self._scan("aaa", "2026-01-01T00:00:00Z", {"192.0.2.10": []})
        with self.assertRaises(compare.CompareError):
            compare.diff_scans(self.db, "aaa", "aaa")

    def test_a_unique_prefix_is_enough_and_an_ambiguous_one_is_refused(self) -> None:
        self._scan("aaa111", "2026-01-01T00:00:00Z", {"192.0.2.10": []})
        self._scan("bbb222", "2026-01-02T00:00:00Z", {"192.0.2.10": []})
        self.assertEqual(compare.resolve_scan(self.db, "bbb").id, "bbb222")
        with self.assertRaises(compare.CompareError):
            compare.resolve_scan(self.db, "zzz")

    def test_recent_scans_are_newest_first(self) -> None:
        self._scan("aaa", "2026-01-01T00:00:00Z", {"192.0.2.10": []})
        self._scan("bbb", "2026-01-02T00:00:00Z", {"192.0.2.10": []})
        self.assertEqual([scan.id for scan in compare.recent_scans(self.db)], ["bbb", "aaa"])

    def test_the_text_report_is_ascii_and_names_both_scans(self) -> None:
        self._scan("aaa", "2026-01-01T00:00:00Z", {"192.0.2.10": [(22, "open", "ssh")]})
        self._scan("bbb", "2026-01-02T00:00:00Z", {})
        output = compare.render_text(compare.diff_scans(self.db, "aaa", "bbb"))
        self.assertIn("before: aaa", output)
        self.assertIn("after:  bbb", output)
        self.assertIn("192.0.2.10", output)
        self.assertTrue(output.isascii())


if __name__ == "__main__":
    unittest.main()
