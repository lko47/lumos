from __future__ import annotations

import unittest

from lumos.core.nmap.xml_stream import (
    NmapXmlError,
    TruncatedNmapXmlError,
    parse_nmap_xml,
    sanitize_text,
)

from pathlib import Path
FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures" / "nmap"


class NmapXmlStreamTests(unittest.TestCase):
    def test_normal_fixture_parses_hosts_ports_os_scripts_and_hops(self) -> None:
        payload = (FIXTURE_DIR / "normal.xml").read_bytes()
        hosts = list(parse_nmap_xml((payload[i:i + 37] for i in range(0, len(payload), 37))))
        self.assertEqual(len(hosts), 1)
        host = hosts[0]
        self.assertEqual(host.state, "up")
        self.assertIn(("ipv4", "192.0.2.10"), [(a.kind, a.value) for a in host.addresses])
        self.assertEqual(host.ports[0].port, 22)
        self.assertEqual(host.ports[0].service, "ssh")
        self.assertEqual(host.os_name, "Example Linux 6.x")
        self.assertTrue(any(s.script_id == "ssh-hostkey" for s in host.scripts))
        self.assertEqual(len(host.hops), 3)
        self.assertFalse(host.hops[1].responded)

    def test_ipv6_fixture_is_parsed_as_an_ipv6_address(self) -> None:
        payload = (FIXTURE_DIR / "ipv6.xml").read_bytes()
        hosts = list(parse_nmap_xml([payload]))
        self.assertEqual(hosts[0].addresses[0].kind, "ipv6")
        self.assertEqual(hosts[0].addresses[0].value, "2001:db8::10")

    def test_dtd_and_entity_declarations_are_rejected(self) -> None:
        payload = (FIXTURE_DIR / "hostile-dtd.xml").read_bytes()
        chunks = [payload[i:i + 5] for i in range(0, len(payload), 5)]
        with self.assertRaisesRegex(NmapXmlError, "DTD|entity"):
            list(parse_nmap_xml(chunks))

    def test_truncated_document_preserves_preceding_completed_host(self) -> None:
        good = (FIXTURE_DIR / "normal.xml").read_bytes()
        first_host = good[good.index(b"  <host "):good.index(b"  </host>") + len(b"  </host>")]
        partial = b'<?xml version="1.0"?><nmaprun>' + first_host + b"<host><status state='up'/>"
        seen = []
        iterator = parse_nmap_xml([partial])
        try:
            while True:
                seen.append(next(iterator))
        except StopIteration:
            pass
        except TruncatedNmapXmlError:
            pass
        self.assertEqual(len(seen), 1)
        self.assertEqual(seen[0].addresses[0].value, "192.0.2.10")

    def test_total_input_size_is_bounded(self) -> None:
        payload = b"<nmaprun>" + b" " * 100 + b"</nmaprun>"
        with self.assertRaisesRegex(NmapXmlError, "size limit"):
            list(parse_nmap_xml([payload], max_bytes=32))

    def test_xml_nesting_depth_is_bounded(self) -> None:
        payload = b"<nmaprun>" + b"<x>" * 8 + b"</x>" * 8 + b"</nmaprun>"
        with self.assertRaisesRegex(NmapXmlError, "nesting limit"):
            list(parse_nmap_xml([payload], max_depth=4))

    def test_text_sanitizer_strips_terminal_escapes_controls_and_caps_length(self) -> None:
        text = "banner\x1b[31mRED\x1b[0m\x00tail"
        self.assertEqual(sanitize_text(text, max_chars=8), "bannerRE")


if __name__ == "__main__":
    unittest.main()
