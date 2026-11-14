"""Hubs that cannot exist, and placeholder hops that must not survive a rebuild.

Both rules come from a review of a screenshot: a map showing `fe80::/64` and
`127.0.0.1/32` hubs, and the same address drawn twice - once as a scanned device
and once as a hollow hop.
"""

from __future__ import annotations

import unittest

from lumos.core.inference import rebuild_inferred
from tests.test_inference import BASE_ROUTES, Scenario, eth0
import tempfile


class HubHygieneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _nodes(self, scan: Scenario):
        return scan.query("SELECT kind, label FROM topology_nodes ORDER BY kind, label")

    def test_link_local_and_loopback_interfaces_never_become_hubs(self) -> None:
        scan = Scenario(
            __import__("pathlib").Path(self.tmp.name),
            interfaces=(
                eth0("198.51.100.32/24"),
                eth0("fe80::1/64", name="wlan0"),
                eth0("169.254.10.5/16", name="eth1"),
                eth0("127.0.0.1/8", name="lo0"),
            ),
            routes=BASE_ROUTES,
        )
        scan.add_host("198.51.100.40", reason="arp")
        rebuild_inferred(scan.db)
        zones = [row["label"] for row in self._nodes(scan) if row["kind"] == "zone"]
        self.assertEqual(len(zones), 1, zones)
        self.assertIn("198.51.100.0/24", zones[0])
        joined = " ".join(zones)
        self.assertNotIn("fe80", joined)
        self.assertNotIn("169.254", joined)
        self.assertNotIn("127.", joined)

    def test_a_scanned_gateway_replaces_its_placeholder(self) -> None:
        scan = Scenario(__import__("pathlib").Path(self.tmp.name), interfaces=(eth0(),), routes=BASE_ROUTES)
        scan.add_host("203.0.113.5", reason="syn-ack")
        rebuild_inferred(scan.db)
        placeholders = [row for row in self._nodes(scan) if row["kind"] == "unknown_hop"]
        self.assertEqual(len(placeholders), 1, "the gateway starts as a hollow hop")

        # Now the gateway itself gets scanned: the hollow node must go away.
        scan.add_host("198.51.100.1", reason="arp")
        rebuild_inferred(scan.db)
        labels = [row["label"] for row in self._nodes(scan)]
        self.assertEqual(labels.count("198.51.100.1"), 1, labels)
        self.assertEqual(
            [row for row in self._nodes(scan) if row["kind"] == "unknown_hop"], [],
            "no hollow twin may survive the host being scanned",
        )
        gateway_edges = [
            row for row in scan.edges() if row["source_kind"] == "rule:gateway_on_link"
        ]
        self.assertEqual(len(gateway_edges), 1)
        self.assertEqual(gateway_edges[0]["to_kind"], "device")


if __name__ == "__main__":
    unittest.main()
