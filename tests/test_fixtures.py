from __future__ import annotations

import unittest
import xml.etree.ElementTree as ET
from pathlib import Path

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "nmap"


class NmapFixtureTests(unittest.TestCase):
    def test_normal_fixture_is_well_formed_and_covers_core_fields(self) -> None:
        root = ET.parse(FIXTURES / "normal.xml").getroot()
        self.assertEqual(root.tag, "nmaprun")
        self.assertIsNotNone(root.find("host/ports/port/state[@state='filtered']"))
        self.assertIsNotNone(root.find("host/os/osmatch"))
        self.assertIsNotNone(root.find("host/trace/hop[@ttl='2']"))
        self.assertIsNotNone(root.find("host/ports/port/script"))

    def test_ipv6_fixture_is_well_formed(self) -> None:
        root = ET.parse(FIXTURES / "ipv6.xml").getroot()
        address = root.find("host/address")
        self.assertEqual(address.attrib["addrtype"], "ipv6")
        self.assertEqual(address.attrib["addr"], "2001:db8::10")

    def test_truncated_fixture_is_incomplete_xml(self) -> None:
        with self.assertRaises(ET.ParseError):
            ET.parse(FIXTURES / "truncated.xml")

    def test_hostile_fixture_contains_entity_declaration_for_rejection_tests(self) -> None:
        text = (FIXTURES / "hostile-dtd.xml").read_text(encoding="utf-8")
        self.assertIn("<!DOCTYPE", text)
        self.assertIn("<!ENTITY", text)
        self.assertIn("&xxe;", text)


if __name__ == "__main__":
    unittest.main()
