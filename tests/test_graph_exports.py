"""DOT, Mermaid and stored-scan XML: the shapes other tools consume."""

from __future__ import annotations

import gzip
import hashlib
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lumos.core import reports
from lumos.core.database import initialize_database, open_database

EVIDENCE = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV 192.0.2.10" start="1700000000">
<host starttime="1700000001" endtime="1700000002">
<status state="up" reason="syn-ack"/>
<address addr="192.0.2.10" addrtype="ipv4"/>
<hostnames><hostname name="edge&quot;box.example" type="PTR"/></hostnames>
<ports><port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
<service name="ssh" product="OpenSSH" version="9.6"/></port></ports>
</host>
</nmaprun>
"""

HOSTILE_LABEL = 'router "core" of <dmz>'


def _seed(path: Path, *, with_evidence: bool = True) -> str:
    initialize_database(path, "graph export test")
    conn = open_database(path)
    with conn:
        engagement = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()[0]
        scan_id = "scan-1"
        conn.execute(
            "INSERT INTO vantage_points (id, engagement_id, scanner_name, operator, created_at)"
            " VALUES ('v1', ?, 'scanner-host', 'tester', '2026-01-01T00:00:00Z')",
            (engagement,),
        )
        conn.execute(
            "INSERT INTO scans (id, engagement_id, vantage_point_id, exact_args_json,"
            " redacted_args_json, targets_json, started_at, status) VALUES (?, ?, 'v1',"
            " '[]', '[]', '[]', '2026-01-01T00:00:00Z', 'completed')",
            (scan_id, engagement),
        )
        for node_id, kind in (("root", "root"), ("zone", "zone"), ("dev", "device")):
            conn.execute(
                "INSERT INTO topology_nodes (id, engagement_id, kind, label, created_at)"
                " VALUES (?, ?, ?, ?, '2026-01-01T00:00:00Z')",
                (node_id, engagement, kind, HOSTILE_LABEL if kind == "device" else node_id),
            )
        conn.execute(
            "INSERT INTO topology_edges (id, engagement_id, from_node_id, to_node_id,"
            " edge_type, source_kind, confidence, first_observed_at)"
            " VALUES ('e1', ?, 'root', 'zone', 'traceroute', 'scan', 1.0,"
            " '2026-01-01T00:00:00Z')",
            (engagement,),
        )
        conn.execute(
            "INSERT INTO topology_edges (id, engagement_id, from_node_id, to_node_id,"
            " edge_type, source_kind, confidence, first_observed_at)"
            " VALUES ('e2', ?, 'zone', 'dev', 'inferred', 'inference', 0.6,"
            " '2026-01-01T00:00:00Z')",
            (engagement,),
        )
        if with_evidence:
            conn.execute(
                "INSERT INTO raw_scan_evidence (scan_id, compression, byte_length, payload,"
                " sha256, stored_at) VALUES (?, 'gzip', ?, ?, ?, '2026-01-01T00:00:00Z')",
                (scan_id, len(EVIDENCE), gzip.compress(EVIDENCE),
                 hashlib.sha256(EVIDENCE).hexdigest()),
            )
    conn.close()
    return "scan-1"


class DotReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "eng.sqlite"
        _seed(self.path)

    def test_dot_is_a_balanced_digraph_with_quoted_identifiers(self) -> None:
        text = reports.build_dot_report(self.path)
        self.assertTrue(text.startswith("digraph lumos {"))
        self.assertEqual(text.count("{"), text.count("}"))
        self.assertIn('"root" -> "zone"', text, "a measured link is a plain edge")
        self.assertIn("style=\"dashed\"", text, "an inferred link must read as inferred")

    def test_hostile_labels_are_escaped_rather_than_breaking_the_file(self) -> None:
        text = reports.build_dot_report(self.path)
        label_line = next(line for line in text.splitlines() if "router" in line)
        label = label_line.split('label="', 1)[1].split('", shape=', 1)[0]
        self.assertIn('\\"core\\"', label, "quotes inside a label must be escaped")
        self.assertEqual(label.replace('\\"', "").count('"'), 0)

    def test_each_line_of_the_graph_ends_in_a_semicolon_or_brace(self) -> None:
        for line in reports.build_dot_report(self.path).splitlines()[1:-1]:
            self.assertTrue(line.rstrip().endswith(";") or line.rstrip().endswith("{"), line)


class MermaidReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "eng.sqlite"
        _seed(self.path)

    def test_mermaid_declares_a_flowchart_and_only_known_link_syntax(self) -> None:
        text = reports.build_mermaid_report(self.path)
        self.assertTrue(text.startswith("flowchart TD"))
        links = [line.strip() for line in text.splitlines() if "->" in line or "==>" in line]
        self.assertEqual(len(links), 2)
        for line in links:
            self.assertRegex(line, r"^n\d+ (-->|==>|-.+\.->) n\d+$")

    def test_node_labels_cannot_inject_markup(self) -> None:
        text = reports.build_mermaid_report(self.path)
        self.assertNotIn("<dmz>", text)
        self.assertNotIn('"core"', text)


class StoredXmlTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "eng.sqlite"
        self.scan_id = _seed(self.path)

    def test_the_xml_comes_back_out_verbatim_and_reparses(self) -> None:
        text = reports.build_nmap_xml_report(self.path)
        self.assertIn('addr="192.0.2.10"', text)
        hosts = list(reports.parse_nmap_xml([text.encode()]))
        self.assertEqual(len(hosts), 1)
        self.assertEqual([port.port for port in hosts[0].ports], [22])
        self.assertEqual(hosts[0].ports[0].product, "OpenSSH")

    def test_it_refuses_when_no_evidence_was_kept(self) -> None:
        empty = Path(self.tmp.name) / "empty.sqlite"
        _seed(empty, with_evidence=False)
        with self.assertRaises(ValueError):
            reports.build_nmap_xml_report(empty)

    def test_the_writer_sets_owner_only_permissions(self) -> None:
        output = Path(self.tmp.name) / "scan.xml"
        reports.write_nmap_xml_report(self.path, output)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(reports.stored_scans(self.path)[0][0], self.scan_id)


class FormatWiringTests(unittest.TestCase):
    def test_the_tui_offers_every_format_it_can_write_without_a_scan_id(self) -> None:
        from lumos.core.reports import REPORT_FORMATS as WRITERS
        from lumos.tui import flows

        self.assertEqual(
            set(flows.REPORT_FORMATS), set(WRITERS) - {"nmap-xml"},
            "the chooser must not drift from the writers",
        )


if __name__ == "__main__":
    unittest.main()
