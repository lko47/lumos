from __future__ import annotations

import json
import subprocess
import unittest
from io import StringIO
from unittest.mock import patch

from lumos.cli import main
from lumos.core.nmap.iflist import (
    InterfaceEntry,
    InterfaceSnapshot,
    RouteEntry,
    discover_interfaces,
    parse_iflist_output,
)
from lumos.core.nmap.runner import NmapRunnerError


SYNTHETIC_IFLIST = """Starting Nmap 7.99 ( https://nmap.org ) at 2026-01-01 00:00 UTC
************************INTERFACES************************
DEV       (SHORT)     IP/MASK          TYPE     UP   MTU   MAC
lo        (lo)        127.0.0.1/8      loopback up   65536
eth0      (eth0)      (none)/0         ethernet down 1500 02:00:00:00:00:01
wlan0     (wlan0)     192.0.2.12/24    ethernet up   1500 02:00:00:00:00:02
wlan0     (wlan0)     2001:db8::12/64 ethernet up   1500 02:00:00:00:00:02

**************************ROUTES**************************
DST/MASK       DEV   METRIC GATEWAY
192.0.2.0/24   wlan0 100
0.0.0.0/0      wlan0 100    192.0.2.1
2001:db8::/64  wlan0 256    fe80::1
"""


class NmapIfListTests(unittest.TestCase):
    def test_parser_handles_ipv4_ipv6_down_interfaces_and_direct_routes(self) -> None:
        snapshot = parse_iflist_output(SYNTHETIC_IFLIST)
        self.assertEqual(len(snapshot.interfaces), 4)
        self.assertEqual(snapshot.interfaces[0].address, "127.0.0.1/8")
        self.assertTrue(snapshot.interfaces[0].is_up)
        self.assertIsNone(snapshot.interfaces[1].address)
        self.assertFalse(snapshot.interfaces[1].is_up)
        self.assertEqual(snapshot.interfaces[2].address, "192.0.2.12/24")
        self.assertEqual(snapshot.interfaces[3].address, "2001:db8::12/64")
        self.assertEqual(snapshot.routes[0], RouteEntry("192.0.2.0/24", "wlan0", 100, None))
        self.assertEqual(snapshot.routes[1].gateway, "192.0.2.1")
        self.assertEqual(snapshot.routes[2].gateway, "fe80::1")

    def test_parser_rejects_missing_sections_and_malformed_rows(self) -> None:
        with self.assertRaisesRegex(NmapRunnerError, "both interface and route tables"):
            parse_iflist_output("Starting Nmap 7.99")
        malformed = SYNTHETIC_IFLIST.replace("192.0.2.12/24", "not-an-address")
        with self.assertRaisesRegex(NmapRunnerError, "Invalid interface address"):
            parse_iflist_output(malformed)
        malformed_route = SYNTHETIC_IFLIST.replace("192.0.2.0/24", "not-a-network")
        with self.assertRaisesRegex(NmapRunnerError, "Invalid route destination"):
            parse_iflist_output(malformed_route)

    def test_parser_enforces_output_size_limit(self) -> None:
        with self.assertRaisesRegex(NmapRunnerError, "1 MiB safety limit"):
            parse_iflist_output("x" * (1024 * 1024 + 1))

    def test_discovery_invokes_only_nmap_iflist_without_shell(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["/opt/nmap", "--iflist"], returncode=0, stdout=SYNTHETIC_IFLIST, stderr=""
        )
        with patch("lumos.core.nmap.iflist.find_nmap", return_value="/opt/nmap"), patch(
            "lumos.core.nmap.iflist.subprocess.run", return_value=completed
        ) as run:
            snapshot = discover_interfaces()
        self.assertEqual(snapshot.interfaces[0].name, "lo")
        run.assert_called_once()
        args, kwargs = run.call_args
        self.assertEqual(args[0], ["/opt/nmap", "--iflist"])
        self.assertIs(kwargs["shell"], False)
        self.assertEqual(kwargs["timeout"], 15)

    def test_discovery_reports_nmap_failure(self) -> None:
        completed = subprocess.CompletedProcess(
            args=["/opt/nmap", "--iflist"], returncode=2, stdout="", stderr="permission issue"
        )
        with patch("lumos.core.nmap.iflist.find_nmap", return_value="/opt/nmap"), patch(
            "lumos.core.nmap.iflist.subprocess.run", return_value=completed
        ):
            with self.assertRaisesRegex(NmapRunnerError, "exit code 2: permission issue"):
                discover_interfaces()

    def test_cli_json_and_text_outputs(self) -> None:
        snapshot = InterfaceSnapshot(
            (InterfaceEntry("eth0", "eth0", "192.0.2.12/24", "ethernet", True, 1500, "02:00:00:00:00:02"),),
            (RouteEntry("0.0.0.0/0", "eth0", 100, "192.0.2.1"),),
        )
        with patch("lumos.cli.discover_interfaces", return_value=snapshot), patch("sys.stdout", new_callable=StringIO) as output:
            self.assertEqual(main(["interfaces", "--json"]), 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["interfaces"][0]["address"], "192.0.2.12/24")
        self.assertEqual(payload["routes"][0]["gateway"], "192.0.2.1")

        with patch("lumos.cli.discover_interfaces", return_value=snapshot), patch("sys.stdout", new_callable=StringIO) as output:
            self.assertEqual(main(["interfaces"]), 0)
        self.assertIn("eth0", output.getvalue())
        self.assertIn("192.0.2.1", output.getvalue())


if __name__ == "__main__":
    unittest.main()
