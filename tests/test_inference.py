"""Acceptance tests for the inference engine (spec: inferred map links)."""

from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lumos.core import ids
from lumos.core.database import initialize_database, open_database, utc_now
from lumos.core.inference import rebuild_inferred
from lumos.services.map_view import load_map_snapshot
from lumos.core.nmap.iflist import InterfaceEntry, InterfaceSnapshot, RouteEntry
from lumos.core.vantage_store import save_interfaces


def eth0(address: str = "192.0.2.32/24", name: str = "eth0") -> InterfaceEntry:
    prefix = int(address.rsplit("/", 1)[1])
    return InterfaceEntry(
        name=name,
        short_name=name,
        address=address,
        interface_type="ethernet",
        is_up=True,
        mtu=1500,
        mac="aa:bb:cc:dd:ee:ff",
        prefix_len=prefix,
        family=4 if ":" not in address else 6,
    )


class Scenario:
    """One engagement, one scanner, synthetic hosts in a controlled layout."""

    def __init__(self, tmp: Path, interfaces=(), routes=()) -> None:
        self.db = tmp / "engagement.sqlite"
        initialize_database(self.db, "inference test")
        save_interfaces(
            self.db,
            InterfaceSnapshot(tuple(interfaces), tuple(routes)),
            scanner_name="scanner-a",
            operator="analyst",
        )
        conn = open_database(self.db, readonly=False)
        try:
            self.uid = ids.ensure_engagement_uid(conn)
            self.engagement_id = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()[0]
            self.network_id = ids.network_id(self.uid, "lab")
            self.scan_id = ids.trace_path_id(self.uid, "scan", 0)
            with conn:
                conn.execute(
                    "INSERT INTO networks(id, engagement_id, name, cidr, family, notes, created_at) "
                    "VALUES (?, ?, 'lab', NULL, NULL, '', ?)",
                    (self.network_id, self.engagement_id, utc_now()),
                )
                conn.execute(
                    "INSERT INTO scans(id, engagement_id, vantage_point_id, exact_args_json, "
                    "redacted_args_json, targets_json, nmap_version, interface, operator, started_at, "
                    "exit_code, status) VALUES (?, ?, ?, '[]', '[]', '{}', '7.98', 'eth0', 'analyst', ?, 0, 'completed')",
                    (
                        self.scan_id,
                        self.engagement_id,
                        ids.vantage_id(self.uid, "scanner-a"),
                        utc_now(),
                    ),
                )
        finally:
            conn.close()
        self.hosts = 0

    def add_host(
        self,
        address: str,
        *,
        reason: str = "",
        mac: str = "",
        reason_ttl: int | None = 64,
        hostname: str = "",
        device_id: str | None = None,
        seen: int = 0,
    ) -> tuple[str, str]:
        conn = open_database(self.db, readonly=False)
        try:
            now = utc_now()
            device_id = device_id or ids.device_id(self.uid, self.scan_id, self.hosts)
            self.hosts += 1
            observation_id = ids.observation_id(device_id)
            node_id = ids.node_id(self.uid, "device", device_id)
            address_id = ids.address_id(self.network_id, "ipv4", address)
            with conn:
                conn.execute(
                    "INSERT INTO devices(id, engagement_id, created_at) VALUES (?, ?, ?)",
                    (device_id, self.engagement_id, now),
                )
                conn.execute(
                    "INSERT INTO host_observations(id, scan_id, device_id, observed_at, reachability, "
                    "discovery_method, hostname, os_name, os_accuracy, mac_vendor, latency_seconds, "
                    "raw_host_json, reason, reason_ttl, mac) "
                    "VALUES (?, ?, ?, ?, 'up', ?, ?, '', NULL, '', 0.001, '{}', ?, ?, ?)",
                    (observation_id, self.scan_id, device_id, now, reason or "syn-ack", hostname, reason, reason_ttl, mac),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO addresses(id, network_id, kind, normalized_value, display_value, created_at) "
                    "VALUES (?, ?, 'ipv4', ?, ?, ?)",
                    (address_id, self.network_id, address, address, now),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO observation_addresses(host_observation_id, address_id, role) "
                    "VALUES (?, ?, 'ipv4')",
                    (observation_id, address_id),
                )
                conn.execute(
                    "INSERT OR IGNORE INTO topology_nodes(id, engagement_id, kind, entity_id, label, created_at) "
                    "VALUES (?, ?, 'device', ?, ?, ?)",
                    (node_id, self.engagement_id, device_id, hostname or address, now),
                )
            return node_id, device_id
        finally:
            conn.close()

    def query(self, sql: str, params=()):
        conn = open_database(self.db, readonly=True)
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    def edges(self):
        return self.query(
            "SELECT e.edge_type, e.source_kind, e.confidence, f.kind AS from_kind, t.kind AS to_kind, "
            "f.label AS from_label, t.label AS to_label, e.evidence_json "
            "FROM topology_edges e "
            "JOIN topology_nodes f ON f.id = e.from_node_id "
            "JOIN topology_nodes t ON t.id = e.to_node_id "
            "ORDER BY e.edge_type, e.confidence, e.id"
        )

    def root_to_host_edges(self):
        return [
            row
            for row in self.edges()
            if row["from_kind"] == "root" and row["to_kind"] == "device"
        ]


BASE_ROUTES = (
    RouteEntry(destination="192.0.2.0/24", device="eth0", metric=100, gateway=None),
    RouteEntry(destination="default", device="eth0", metric=100, gateway="192.0.2.1"),
)


class InferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def scenario(self, interfaces=None, routes=BASE_ROUTES) -> Scenario:
        if interfaces is None:
            interfaces = (eth0(),)
        return Scenario(Path(self.tmp.name), interfaces, routes)

    def test_privileged_sweep_uses_one_hub_and_arp_links(self) -> None:
        scan = self.scenario()
        for index in range(20):
            scan.add_host(f"192.0.2.{100 + index}", reason="arp-response", mac=f"02:00:00:00:00:{index:02x}")
        stats = rebuild_inferred(scan.db)
        self.assertEqual(stats.hubs, 1)
        self.assertEqual(stats.local_edges, 1)
        edges = scan.edges()
        local = [row for row in edges if row["edge_type"] == "local"]
        inferred = [row for row in edges if row["edge_type"] == "inferred"]
        self.assertEqual(len(local), 1)
        self.assertEqual(local[0]["from_kind"], "root")
        self.assertEqual(local[0]["to_kind"], "zone")
        self.assertEqual(len(inferred), 20)
        self.assertTrue(all(row["confidence"] == 0.95 for row in inferred))
        self.assertTrue(all(row["source_kind"] == "rule:on_link_arp" for row in inferred))
        self.assertEqual(scan.root_to_host_edges(), [])

    def test_unprivileged_sweep_falls_back_to_address_evidence(self) -> None:
        scan = self.scenario()
        for index in range(20):
            scan.add_host(f"192.0.2.{100 + index}", reason="syn-ack")
        rebuild_inferred(scan.db)
        inferred = [row for row in scan.edges() if row["edge_type"] == "inferred"]
        self.assertEqual(len(inferred), 20)
        self.assertTrue(all(row["confidence"] == 0.7 for row in inferred))
        self.assertTrue(all(row["source_kind"] == "rule:on_link_address" for row in inferred))

    def test_routed_target_goes_through_the_gateway(self) -> None:
        scan = self.scenario()
        scan.add_host("198.51.100.5", reason="syn-ack")
        scan.add_host("198.51.100.6", reason="syn-ack")
        rebuild_inferred(scan.db)
        edges = scan.edges()
        gateway_edges = [row for row in edges if row["source_kind"] == "rule:gateway_on_link"]
        self.assertEqual(len(gateway_edges), 1)
        self.assertIn("192.0.2.1", gateway_edges[0]["to_label"])
        self.assertEqual(gateway_edges[0]["confidence"], 0.9)
        hub_edges = [
            row for row in edges if row["source_kind"] == "rule:routed_via_gateway"
            and row["to_kind"] == "zone"
        ]
        self.assertEqual(len(hub_edges), 1)
        self.assertEqual(hub_edges[0]["confidence"], 0.5)
        self.assertTrue(hub_edges[0]["to_label"].startswith("~198.51.100.0/24"))
        host_edges = [
            row for row in edges if row["source_kind"] == "rule:routed_via_gateway"
            and row["to_kind"] == "device"
        ]
        self.assertEqual(len(host_edges), 2)
        self.assertTrue(all(row["confidence"] == 0.4 for row in host_edges))

    def test_unknown_vantage_is_marked_and_stays_on_its_own_root(self) -> None:
        scan = self.scenario(interfaces=(), routes=())
        scan.add_host("192.0.2.77", reason="syn-ack")
        rebuild_inferred(scan.db)
        edges = scan.edges()
        root_edges = [row for row in edges if row["from_kind"] == "root"]
        self.assertEqual(len(root_edges), 1)
        self.assertEqual(root_edges[0]["confidence"], 0.2)
        self.assertIn("path unknown", root_edges[0]["to_label"] + root_edges[0]["evidence_json"])
        host_edges = [row for row in edges if row["to_kind"] == "device"]
        self.assertEqual(len(host_edges), 1)
        self.assertEqual(host_edges[0]["confidence"], 0.4)

    def test_observed_path_suppresses_the_inferred_link_only(self) -> None:
        scan = self.scenario()
        traced, _ = scan.add_host("192.0.2.50", reason="arp-response", mac="02:00:00:00:00:aa")
        plain, _ = scan.add_host("192.0.2.51", reason="arp-response", mac="02:00:00:00:00:bb")
        # Record a traceroute path for the first host.
        conn = open_database(scan.db, readonly=False)
        try:
            with conn:
                path_id = ids.trace_path_id(scan.scan_id, traced, 0)
                conn.execute(
                    "INSERT INTO trace_paths(id, scan_id, vantage_point_id, root_node_id, "
                    "destination_node_id, path_index, observed_at) "
                    "SELECT ?, ?, id, NULL, ?, 0, ? FROM vantage_points WHERE scanner_name = 'scanner-a'",
                    (path_id, scan.scan_id, traced, utc_now()),
                )
                root = conn.execute(
                    "SELECT id FROM topology_nodes WHERE kind = 'root' LIMIT 1"
                ).fetchone()[0]
                conn.execute(
                    "INSERT INTO trace_hops(id, trace_path_id, hop_number, address_text, responded) "
                    "VALUES (?, ?, 1, '192.0.2.1', 1)",
                    (ids.trace_hop_id(path_id, 1), path_id),
                )
                conn.execute(
                    "INSERT INTO trace_hops(id, trace_path_id, hop_number, address_text, responded) "
                    "VALUES (?, ?, 2, '192.0.2.50', 1)",
                    (ids.trace_hop_id(path_id, 2), path_id),
                )
                conn.execute("UPDATE trace_paths SET root_node_id = ? WHERE id = ?", (root, path_id))
        finally:
            conn.close()
        rebuild_inferred(scan.db)
        host_edges = [row for row in scan.edges() if row["to_kind"] == "device"]
        self.assertEqual(len(host_edges), 1)
        self.assertIn("192.0.2.51", host_edges[0]["to_label"])
        memberships = scan.query("SELECT COUNT(*) FROM zone_memberships WHERE topology_node_id IN (?, ?)", (traced, plain))
        self.assertEqual(memberships[0][0], 2)

    def test_rebuild_is_deterministic_and_confirms_instead_of_duplicating(self) -> None:
        scan = self.scenario()
        for index in range(5):
            scan.add_host(f"192.0.2.{100 + index}", reason="arp-response", mac=f"02:00:00:00:01:{index:02x}")
        rebuild_inferred(scan.db)
        first = [(row["edge_type"], row["from_label"], row["to_label"], row["confidence"]) for row in scan.edges()]
        stamp = scan.query("SELECT first_observed_at, last_confirmed_at FROM topology_edges LIMIT 1")[0]
        rebuild_inferred(scan.db)
        second = [(row["edge_type"], row["from_label"], row["to_label"], row["confidence"]) for row in scan.edges()]
        self.assertEqual(first, second)
        again = scan.query("SELECT first_observed_at, last_confirmed_at FROM topology_edges LIMIT 1")[0]
        self.assertEqual(stamp[0], again[0])
        self.assertGreaterEqual(again[1], stamp[1])

    def test_rejected_edge_stays_gone_across_rebuilds(self) -> None:
        scan = self.scenario()
        node, _ = scan.add_host("192.0.2.100", reason="arp-response", mac="02:00:00:00:02:00")
        rebuild_inferred(scan.db)
        edge = scan.query(
            "SELECT id FROM topology_edges WHERE edge_type = 'inferred' LIMIT 1"
        )[0][0]
        conn = open_database(scan.db, readonly=False)
        try:
            with conn:
                conn.execute(
                    "INSERT INTO edge_decisions(id, engagement_id, edge_id, decision, author, created_at) "
                    "VALUES (?, ?, ?, 'rejected', 'analyst', ?)",
                    (str(ids.review_item_id(scan.uid, "edge", edge, "reject")), scan.engagement_id, edge, utc_now()),
                )
        finally:
            conn.close()
        rebuild_inferred(scan.db)
        self.assertEqual(scan.query("SELECT COUNT(*) FROM topology_edges WHERE id = ?", (edge,))[0][0], 0)

    def test_proxy_arp_downgrades_and_raises_one_review(self) -> None:
        scan = self.scenario()
        for index in range(30):
            scan.add_host(
                f"192.0.2.{10 + index}", reason="arp-response", mac="02:00:00:00:03:00"
            )
        rebuild_inferred(scan.db)
        inferred = [row for row in scan.edges() if row["edge_type"] == "inferred"]
        self.assertEqual(len(inferred), 30)
        self.assertTrue(all(row["confidence"] == 0.7 for row in inferred))
        self.assertTrue(all(row["source_kind"] == "rule:on_link_address" for row in inferred))
        items = scan.query("SELECT target_kind, target_id FROM review_items WHERE reason_code = 'proxy_arp_suspected'")
        self.assertEqual(len(items), 1)
        self.assertEqual(items[0][1], "02:00:00:00:03:00")

    def test_tunnel_interface_never_claims_arp_evidence(self) -> None:
        scan = self.scenario(
            interfaces=(eth0("192.0.2.32/24"), eth0("10.8.0.2/24", name="tun0")),
            routes=(RouteEntry(destination="10.8.0.0/24", device="tun0", metric=50, gateway=None),),
        )
        scan.add_host("10.8.0.9", reason="arp-response", mac="02:00:00:00:04:00")
        rebuild_inferred(scan.db)
        inferred = [row for row in scan.edges() if row["edge_type"] == "inferred"]
        self.assertEqual(len(inferred), 1)
        self.assertEqual(inferred[0]["confidence"], 0.7)
        self.assertIn("tun0", inferred[0]["evidence_json"])

    def test_ipv6_prefix_behaves_like_ipv4(self) -> None:
        scan = self.scenario(
            interfaces=(eth0("2001:db8:1::10/64"),),
            routes=(RouteEntry(destination="2001:db8:1::/64", device="eth0", metric=100, gateway=None),),
        )
        scan.add_host("2001:db8:1::20", reason="ndr", mac="02:00:00:00:05:00")
        rebuild_inferred(scan.db)
        inferred = [row for row in scan.edges() if row["edge_type"] == "inferred"]
        self.assertEqual(len(inferred), 1)
        self.assertEqual(inferred[0]["confidence"], 0.95)

    def test_hub_ids_are_keyed_on_network_and_cidr(self) -> None:
        # Two engagements naming the same CIDR in different networks must not
        # share a hub id; identical inputs must always derive the same id.
        uid = ids.engagement_uid("engagement", "2026-11-11T00:00:00Z")
        first = ids.zone_id(uid, "network-a", "10.0.0.0/24")
        second = ids.zone_id(uid, "network-b", "10.0.0.0/24")
        self.assertNotEqual(first, second)
        self.assertEqual(first, ids.zone_id(uid, "network-a", "10.0.0.0/24"))

    def test_rebuild_removes_stale_derived_hubs_but_keeps_user_zones(self) -> None:
        scan = self.scenario()
        scan.add_host("192.0.2.100", reason="syn-ack")
        rebuild_inferred(scan.db)
        conn = open_database(scan.db, readonly=False)
        try:
            with conn:
                conn.execute(
                    "INSERT INTO zones(id, engagement_id, name, zone_type, description, author, created_at, "
                    "derived, cidr, network_id) VALUES ('user-zone', ?, 'drawn by hand', 'subnet', '', 'analyst', ?, "
                    "0, '', NULL)",
                    (scan.engagement_id, utc_now()),
                )
                conn.execute(
                    "INSERT INTO zones(id, engagement_id, name, zone_type, description, author, created_at, "
                    "derived, cidr, network_id) VALUES ('stale-hub', ?, '198.18.0.0/16', 'segment', '', 'lumos', ?, "
                    "1, '198.18.0.0/16', NULL)",
                    (scan.engagement_id, utc_now()),
                )
        finally:
            conn.close()
        rebuild_inferred(scan.db)
        remaining = {row[0] for row in scan.query("SELECT id FROM zones")}
        self.assertIn("user-zone", remaining)
        self.assertNotIn("stale-hub", remaining)


class CollapseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_hub_above_the_threshold_is_one_node_with_a_count(self) -> None:
        scan = Scenario(Path(self.tmp.name), (eth0(),), BASE_ROUTES)
        for index in range(60):
            scan.add_host(f"192.0.2.{index + 2}", reason="arp-response", mac=f"02:00:00:10:00:{index:02x}")
        rebuild_inferred(scan.db)
        snapshot = load_map_snapshot(scan.db)
        hubs = [node for node in snapshot.nodes if node.kind == "zone"]
        self.assertEqual(len(hubs), 1)
        self.assertEqual(hubs[0].member_count, 60)
        self.assertEqual([node.kind for node in snapshot.nodes if node.kind == "device"], [])
        self.assertEqual(snapshot.not_shown, 60)
        self.assertEqual([edge.edge_type for edge in snapshot.edges], ["local"])

    def test_small_hub_keeps_its_members_visible(self) -> None:
        scan = Scenario(Path(self.tmp.name), (eth0(),), BASE_ROUTES)
        for index in range(5):
            scan.add_host(f"192.0.2.{index + 2}", reason="syn-ack")
        rebuild_inferred(scan.db)
        snapshot = load_map_snapshot(scan.db)
        self.assertEqual(len([n for n in snapshot.nodes if n.kind == "device"]), 5)
        self.assertEqual(snapshot.not_shown, 0)


if __name__ == "__main__":
    unittest.main()
