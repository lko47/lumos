"""JSON, CSV and HTML exports: same data, three shapes, all escaped."""

from __future__ import annotations

import csv
import io
import json
import tempfile
import unittest
from pathlib import Path

from lumos.core import reports
from lumos.core.database import initialize_database, open_database

HOSTILE = 'edge"<script>alert(1)</script>'


class ReportExportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = Path(self.tmp.name) / "export.sqlite"
        initialize_database(self.db, "export test")
        conn = open_database(self.db)
        with conn:
            engagement = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()[0]
            conn.execute(
                "INSERT INTO vantage_points (id, engagement_id, scanner_name, operator, created_at)"
                " VALUES ('v1', ?, 'scanner-host', 'tester', '2026-01-01T00:00:00Z')",
                (engagement,),
            )
            conn.execute(
                "INSERT INTO networks (id, engagement_id, name, cidr, created_at)"
                " VALUES ('n1', ?, 'lab', '192.0.2.0/24', '2026-01-01T00:00:00Z')",
                (engagement,),
            )
            conn.execute(
                "INSERT INTO scans (id, engagement_id, vantage_point_id, exact_args_json,"
                " redacted_args_json, targets_json, started_at, status)"
                " VALUES ('scan-1', ?, 'v1', '[]', '[]', '[\"192.0.2.0/24\"]',"
                " '2026-01-01T00:00:00Z', 'completed')",
                (engagement,),
            )
            conn.execute(
                "INSERT INTO addresses (id, network_id, kind, normalized_value, display_value,"
                " created_at) VALUES ('a1', 'n1', 'ipv4', '192.0.2.10', '192.0.2.10',"
                " '2026-01-01T00:00:00Z')"
            )
            conn.execute(
                "INSERT INTO devices (id, engagement_id, created_at)"
                " VALUES ('d1', ?, '2026-01-01T00:00:00Z')", (engagement,)
            )
            conn.execute(
                "INSERT INTO host_observations (id, scan_id, device_id, observed_at, hostname)"
                " VALUES ('h1', 'scan-1', 'd1', '2026-01-01T00:00:00Z', ?)", (HOSTILE,)
            )
            conn.execute(
                "INSERT INTO observation_addresses (host_observation_id, address_id)"
                " VALUES ('h1', 'a1')"
            )
            conn.execute(
                "INSERT INTO port_observations (id, host_observation_id, protocol, port, state,"
                " service) VALUES ('p1', 'h1', 'tcp', 22, 'open', 'ssh')"
            )
            conn.execute(
                "INSERT INTO topology_nodes (id, engagement_id, kind, entity_id, label, created_at)"
                " VALUES ('n-root', ?, 'root', 'v1', 'scanner-host', '2026-01-01T00:00:00Z')",
                (engagement,),
            )
            conn.execute(
                "INSERT INTO topology_nodes (id, engagement_id, kind, entity_id, label, created_at)"
                " VALUES ('n-dev', ?, 'device', 'd1', '192.0.2.10', '2026-01-01T00:00:00Z')",
                (engagement,),
            )
            conn.execute(
                "INSERT INTO topology_edges (id, engagement_id, from_node_id, to_node_id,"
                " edge_type, source_kind, confidence, first_observed_at, last_confirmed_at, author)"
                " VALUES ('e1', ?, 'n-root', 'n-dev', 'inferred', 'unknown_path', 0.2,"
                " '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', 'test')",
                (engagement,),
            )
        conn.close()

    def test_json_export_is_structured_and_stable(self) -> None:
        first = json.dumps(reports.build_json_report(self.db), sort_keys=True)
        second = json.dumps(reports.build_json_report(self.db), sort_keys=True)
        self.assertEqual(first, second, "an export of unchanged data must be byte-identical")
        payload = reports.build_json_report(self.db)
        self.assertEqual(payload["format"], "lumos-engagement")
        self.assertEqual(payload["hosts"][0]["address"], "192.0.2.10")
        self.assertEqual(payload["hosts"][0]["ports"][0]["port"], 22)
        self.assertEqual(payload["links"][0]["type"], "inferred")
        self.assertEqual(payload["scans"][0]["status"], "completed")

    def test_a_hostile_hostname_does_not_break_the_json(self) -> None:
        payload = reports.build_json_report(self.db)
        self.assertIn("<script>", payload["hosts"][0]["hostname"])
        self.assertIsInstance(json.dumps(payload), str)

    def test_csv_has_one_row_per_port_and_quotes_properly(self) -> None:
        text = reports.build_csv_report(self.db)
        rows = list(csv.DictReader(io.StringIO(text)))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["port"], "22")
        self.assertEqual(rows[0]["service"], "ssh")
        self.assertEqual(rows[0]["hostname"], HOSTILE)

    def test_html_is_escaped_and_has_no_script(self) -> None:
        page = reports.build_html_report(self.db)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("192.0.2.10", page)
        self.assertIn("inferred", page)

    def test_reports_are_written_owner_only_and_refuse_symlinks(self) -> None:
        target = Path(self.tmp.name) / "out" / "report.json"
        reports.write_json_report(self.db, target)
        self.assertEqual(target.stat().st_mode & 0o777, 0o600)
        link = Path(self.tmp.name) / "link.json"
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            reports.write_json_report(self.db, link)


if __name__ == "__main__":
    unittest.main()
