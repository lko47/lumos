from __future__ import annotations

import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lumos.core.database import initialize_database
from lumos.core.reports import _code, _fenced_block, write_markdown_report
from lumos.core.scope_store import add_scope_rule
from lumos.core.xml_import import import_nmap_xml

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "nmap" / "normal.xml"


class MarkdownReportTests(unittest.TestCase):
    def test_empty_report_matches_golden_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "report.sqlite"
            report = Path(tmp) / "report.md"
            with patch("lumos.core.database.utc_now", return_value="2026-01-02T03:04:05.000000Z"):
                initialize_database(db, "Golden demo")
            write_markdown_report(db, report)
            golden = Path(__file__).parent / "golden" / "empty-engagement.md"
            self.assertEqual(report.read_text(encoding="utf-8"), golden.read_text(encoding="utf-8"))

    def test_untrusted_markdown_delimiters_do_not_escape_code_containers(self) -> None:
        self.assertEqual(_code("title\n## forged ` heading"), "``title ## forged ` heading``")
        block = _fenced_block("result\n```\n## forged heading")
        self.assertTrue(block.startswith("````text\n"))
        self.assertTrue(block.endswith("\n````\n"))

    def test_report_refuses_symlink_output(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "report.sqlite"
            victim = Path(tmp) / "important.txt"
            link = Path(tmp) / "report.md"
            initialize_database(db, "Report test")
            victim.write_text("untouched", encoding="utf-8")
            link.symlink_to(victim)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                write_markdown_report(db, link)
            self.assertEqual(victim.read_text(encoding="utf-8"), "untouched")

    def test_report_includes_scan_provenance_assets_ports_and_review(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            db = Path(tmp) / "report.sqlite"
            report = Path(tmp) / "report.md"
            initialize_database(db, "Report test")
            add_scope_rule(db, "lab", "192.0.2.0/24", included=True, author="tester")
            import_nmap_xml(db, "lab", FIXTURE, operator="tester")
            write_markdown_report(db, report)
            text = report.read_text(encoding="utf-8")
            self.assertIn("# Engagement: `Report test`", text)
            self.assertIn("Nmap version: `7.99`", text)
            self.assertIn("demo-host.example.invalid", text)
            self.assertIn("tcp/22", text)
            self.assertIn("Review queue", text)
            self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)


if __name__ == "__main__":
    unittest.main()
