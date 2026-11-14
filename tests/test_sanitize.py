"""Sanitised exports: deterministic, complete, and provably free of originals."""

from __future__ import annotations

import gzip
import hashlib
import ipaddress
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lumos.core.database import check_database, initialize_database, open_database
from lumos.services import sanitize

SECRET_HOST = "198.51.100.77"  # documentation range: the fixture may not be private
SECRET_NAME = "core-sw-01.lab.internal"
SECRET_MAC = "aa:bb:cc:11:22:33"
EVIDENCE = (
    '<nmaprun><host><address addr="198.51.100.77" addrtype="ipv4"/>'
    "<hostnames><hostname name=\"core-sw-01.lab.internal\"/></hostnames>"
    "</host></nmaprun>"
)


def _build(path: Path) -> None:
    initialize_database(path, "sanitise test")
    conn = open_database(path)
    with conn:
        engagement = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()[0]
        conn.execute(
            "INSERT INTO vantage_points (id, engagement_id, scanner_name, operator, created_at)"
            " VALUES ('v1', ?, 'scanner-host', 'tester', '2026-01-01T00:00:00Z')",
            (engagement,),
        )
        conn.execute(
            "INSERT INTO networks (id, engagement_id, name, cidr, created_at)"
            " VALUES ('n1', ?, 'core', '198.51.100.0/24', '2026-01-01T00:00:00Z')",
            (engagement,),
        )
        conn.execute(
            "INSERT INTO addresses (id, network_id, kind, normalized_value, display_value,"
            " created_at) VALUES ('a1', 'n1', 'ipv4', ?, ?, '2026-01-01T00:00:00Z')",
            (SECRET_HOST, SECRET_HOST),
        )
        conn.execute(
            "INSERT INTO addresses (id, network_id, kind, normalized_value, display_value,"
            " created_at) VALUES ('a2', 'n1', 'mac', ?, ?, '2026-01-01T00:00:00Z')",
            (SECRET_MAC, SECRET_MAC),
        )
        conn.execute(
            "INSERT INTO scans (id, engagement_id, vantage_point_id, exact_args_json,"
            " redacted_args_json, targets_json, started_at, status)"
            " VALUES ('s1', ?, 'v1', '[\"nmap\",\"198.51.100.0/24\"]', '[]',"
            " '[\"198.51.100.0/24\"]', '2026-01-01T00:00:00Z', 'completed')",
            (engagement,),
        )
        conn.execute(
            "INSERT INTO devices (id, engagement_id, created_at)"
            " VALUES ('d1', ?, '2026-01-01T00:00:00Z')", (engagement,)
        )
        conn.execute(
            "INSERT INTO host_observations (id, scan_id, device_id, observed_at, hostname,"
            " raw_host_json) VALUES ('h1', 's1', 'd1', '2026-01-01T00:00:00Z', ?, ?)",
            (SECRET_NAME, '{"addr": "' + SECRET_HOST + '"}'),
        )
        conn.execute(
            "INSERT INTO observation_addresses (host_observation_id, address_id)"
            " VALUES ('h1', 'a1')"
        )
        conn.execute(
            "INSERT INTO notes (id, engagement_id, target_kind, target_id, body_markdown,"
            " author, created_at, updated_at)"
            " VALUES ('nt1', ?, 'engagement', NULL, ?, 'tester',"
            " '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z')",
            (engagement, f"the switch at {SECRET_HOST} trunked to {SECRET_NAME}"),
        )
        body = EVIDENCE.encode("utf-8")
        conn.execute(
            "INSERT INTO raw_scan_evidence (scan_id, compression, byte_length, payload, sha256,"
            " stored_at) VALUES ('s1', 'gzip', ?, ?, ?, '2026-01-01T00:00:00Z')",
            (len(body), gzip.compress(body), hashlib.sha256(body).hexdigest()),
        )
    conn.close()


class SanitizeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.src = Path(self.tmp.name) / "eng.sqlite"
        _build(self.src)
        self.out = Path(self.tmp.name) / "export.sqlite"

    def _stats(self) -> sanitize.SanitizeStats:
        return sanitize.export_sanitised(self.src, self.out, overwrite=True)

    def test_the_source_is_untouched(self) -> None:
        before = hashlib.sha256(self.src.read_bytes()).hexdigest()
        self._stats()
        self.assertEqual(hashlib.sha256(self.src.read_bytes()).hexdigest(), before)

    def test_no_original_value_survives_anywhere(self) -> None:
        self._stats()
        conn = sqlite3.connect(self.out)
        try:
            for table in [r[0] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            )]:
                for column in [r[1] for r in conn.execute(f"PRAGMA table_info({table})")]:
                    for (value,) in conn.execute(f"SELECT {column} FROM {table}"):
                        if isinstance(value, str):
                            # Exact values, not prefixes: a pseudonym may legitimately
                            # land in the same documentation range as the original.
                            for secret in (SECRET_HOST, SECRET_NAME, SECRET_MAC):
                                self.assertNotIn(secret, value, f"{table}.{column}")
            for compression, payload in conn.execute(
                "SELECT compression, payload FROM raw_scan_evidence"
            ):
                text = gzip.decompress(bytes(payload)).decode("utf-8") if compression == "gzip" \
                    else bytes(payload).decode("utf-8")
                self.assertNotIn(SECRET_HOST, text)
                self.assertNotIn(SECRET_NAME, text)
        finally:
            conn.close()

    def test_the_export_is_still_a_valid_engagement(self) -> None:
        self._stats()
        self.assertEqual(check_database(self.out)["integrity"], "ok")
        self.assertEqual(self.out.stat().st_mode & 0o777, 0o600)

    def test_pseudonyms_look_like_addresses_and_are_documentation_ranges(self) -> None:
        self._stats()
        conn = sqlite3.connect(self.out)
        try:
            values = [row[0] for row in conn.execute(
                "SELECT display_value FROM addresses WHERE kind = 'ipv4'"
            )]
            macs = [row[0] for row in conn.execute(
                "SELECT display_value FROM addresses WHERE kind = 'mac'"
            )]
        finally:
            conn.close()
        address = ipaddress.ip_address(values[0])
        documentation = [
            ipaddress.ip_network("192.0.2.0/24"),
            ipaddress.ip_network("198.51.100.0/24"),
            ipaddress.ip_network("203.0.113.0/24"),
        ]
        self.assertTrue(
            any(address in network for network in documentation),
            f"{address} is outside the documentation ranges",
        )
        self.assertNotEqual(str(address), SECRET_HOST)
        self.assertTrue(macs[0].startswith("02:00:"), macs[0])
        self.assertNotEqual(macs[0], SECRET_MAC)

    def test_the_mapping_is_stable_across_runs(self) -> None:
        self._stats()
        first = self._values()
        second_out = Path(self.tmp.name) / "export2.sqlite"
        sanitize.export_sanitised(self.src, second_out, overwrite=True)
        self.assertEqual(first, self._values(second_out))

    def test_two_hosts_never_share_a_pseudonym(self) -> None:
        self._stats()
        conn = sqlite3.connect(self.out)
        try:
            values = [row[0] for row in conn.execute(
                "SELECT display_value FROM addresses WHERE kind = 'ipv4'"
            )]
        finally:
            conn.close()
        self.assertEqual(len(values), len(set(values)))

    def test_it_refuses_to_overwrite_its_source_or_an_existing_file(self) -> None:
        with self.assertRaises(sanitize.SanitizeError):
            sanitize.export_sanitised(self.src, self.src, overwrite=True)
        self.out.write_text("occupied", encoding="utf-8")
        with self.assertRaises(sanitize.SanitizeError):
            sanitize.export_sanitised(self.src, self.out)

    def _values(self, path: Path | None = None) -> list[str]:
        conn = sqlite3.connect(path or self.out)
        try:
            return [row[0] for row in conn.execute("SELECT display_value FROM addresses ORDER BY id")]
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()
