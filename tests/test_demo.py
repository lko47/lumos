"""The demo engagement: generated, self-consistent, and never real data."""

from __future__ import annotations

import ipaddress
import sqlite3
import tempfile
import unittest
from pathlib import Path

from lumos.core.database import check_database
from lumos.services import demo
from lumos.services.map_view import load_map_snapshot

DOCUMENTATION = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
)


class DemoTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "demo.sqlite"

    def test_the_demo_builds_a_complete_engagement(self) -> None:
        stats = demo.build_demo(self.path)
        self.assertGreaterEqual(stats.hosts, 10)
        self.assertGreaterEqual(stats.scans, 5)
        self.assertEqual(stats.zones, 3)
        self.assertGreater(stats.edges, 5)
        self.assertEqual(check_database(self.path)["integrity"], "ok")
        self.assertEqual(self.path.stat().st_mode & 0o777, 0o600)

    def test_zones_are_named_rather_than_guessed(self) -> None:
        demo.build_demo(self.path)
        conn = sqlite3.connect(self.path)
        try:
            names = [row[0] for row in conn.execute("SELECT name FROM zones")]
        finally:
            conn.close()
        self.assertEqual(sorted(names), ["192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24"])

    def test_every_address_is_a_documentation_range_address(self) -> None:
        demo.build_demo(self.path)
        conn = sqlite3.connect(self.path)
        try:
            values = [row[0] for row in conn.execute(
                "SELECT normalized_value FROM addresses WHERE kind = 'ipv4'"
            )]
        finally:
            conn.close()
        self.assertTrue(values)
        for value in values:
            address = ipaddress.ip_address(value)
            self.assertTrue(
                any(address in network for network in DOCUMENTATION),
                f"{value} is not a documentation address",
            )

    def test_hostnames_and_macs_are_obviously_generated(self) -> None:
        demo.build_demo(self.path)
        conn = sqlite3.connect(self.path)
        try:
            hosts = [row[0] for row in conn.execute(
                "SELECT hostname FROM host_observations WHERE hostname <> ''"
            )]
            macs = [row[0] for row in conn.execute(
                "SELECT display_value FROM addresses WHERE kind = 'mac'"
            )]
        finally:
            conn.close()
        self.assertTrue(all(name.endswith(".example") for name in hosts), hosts[:3])
        self.assertTrue(all(mac.startswith("02:00:") for mac in macs), macs[:3])

    def test_the_map_and_compare_have_something_to_show(self) -> None:
        demo.build_demo(self.path)
        # The snapshot is the collapsed view on purpose: one hub per zone.
        snapshot = load_map_snapshot(self.path)
        self.assertGreaterEqual(len(snapshot.nodes), 4)
        conn = sqlite3.connect(self.path)
        try:
            devices = conn.execute(
                "SELECT COUNT(*) FROM topology_nodes WHERE kind = 'device'"
            ).fetchone()[0]
        finally:
            conn.close()
        self.assertGreaterEqual(devices, 11, "hub counts are what make the map readable")
        conn = sqlite3.connect(self.path)
        try:
            states = {row[0] for row in conn.execute(
                "SELECT state FROM port_observations"
            )}
        finally:
            conn.close()
        self.assertIn("open", states)
        self.assertIn("closed", states, "the demo must show a port state change")

    def test_it_refuses_to_clobber_an_existing_file(self) -> None:
        demo.build_demo(self.path)
        with self.assertRaises(demo.DemoError):
            demo.build_demo(self.path)
        demo.build_demo(self.path, overwrite=True)


if __name__ == "__main__":
    unittest.main()
