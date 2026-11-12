"""Derive explainable inferred topology links from stored facts.

The rules read what the scanner actually knows about itself and about each
host: its interfaces with prefixes, its routing table, the host's status
reason (``arp-response``, ``ndr``, ...), its MAC, and the address ranges the
user declared. Nothing here invents a link out of nothing: every derived row
carries the rule that produced it and the row ids it used, in
``topology_edges.evidence_json``.

Precedence: an observed traceroute path from the same vantage point always wins
over an inferred link, and a host that has one gets no inferred link at all.
Hubs are broadcast domains / routed subnets, never devices.

``rebuild_inferred`` is idempotent: ids are UUIDv5 over the engagement, the
network, the CIDR, the endpoints and the rule, so a second rebuild updates
``last_confirmed_at`` instead of duplicating rows, and merging two copies of a
database produces the same ids.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from . import ids
from .database import open_database, utc_now
from .text import sanitize_text

RULE_VERSION = 1

LOCAL_INTERFACE = "local_interface"
ON_LINK_ARP = "on_link_arp"
ON_LINK_ADDRESS = "on_link_address"
GATEWAY_ON_LINK = "gateway_on_link"
ROUTED_VIA_GATEWAY = "routed_via_gateway"
UNKNOWN_PATH = "unknown_path"

CONFIDENCE = {
    LOCAL_INTERFACE: 1.0,
    ON_LINK_ARP: 0.95,
    ON_LINK_ADDRESS: 0.7,
    GATEWAY_ON_LINK: 0.9,
    ROUTED_VIA_GATEWAY: 0.6,
    "routed_via_gateway_assumed": 0.4,
    "unknown_path_hub": 0.2,
    "unknown_path_host": 0.4,
    "routed_hub": 0.5,
}

ARP_REASONS = frozenset({"arp-response", "ndr", "neighbor-discovery"})
PROXY_ARP_THRESHOLD = 10
LOOPBACK_NAME = frozenset({"lo", "lo0"})
VIRTUAL_PREFIXES = ("docker", "br-", "virbr", "veth", "vmnet", "tap", "tun", "wg", "ppp")
MAX_HUBS = 4096


@dataclass(frozen=True)
class RebuildStats:
    hubs: int = 0
    edges: int = 0
    local_edges: int = 0
    memberships: int = 0
    removed_edges: int = 0
    removed_hubs: int = 0
    review_items: int = 0


@dataclass(frozen=True)
class _Network:
    key: tuple[int, int, int]  # (version, prefixlen, masked network int)
    cidr: str
    version: int
    prefixlen: int
    network: int
    zone_id: str = ""
    node_id: str = ""
    assumed: bool = False
    virtual: bool = False
    tunnel: bool = False
    iface: str = ""

    def contains(self, address: int) -> bool:
        mask = _mask(self.version, self.prefixlen)
        return (address & mask) == self.network


@dataclass(frozen=True)
class _Host:
    node_id: str
    device_id: str
    addresses: tuple[tuple[int, int], ...]  # (version, address int)
    reason: str
    reason_ttl: int | None
    mac: str


@dataclass
class _Plan:
    edges: list[tuple[str, str, str, float, dict]] = field(default_factory=list)
    hubs: dict[tuple[int, int, int], _Network] = field(default_factory=dict)
    memberships: list[tuple[str, str]] = field(default_factory=list)  # (zone_id, node_id)


def _mask(version: int, prefixlen: int) -> int:
    bits = 32 if version == 4 else 128
    return ((1 << prefixlen) - 1) << (bits - prefixlen) if prefixlen else 0


def _network_int(version: int, packed: bytes) -> int:
    return int.from_bytes(packed, "big")


def _parse_cidr(text: str) -> tuple[int, int, int, int] | None:
    """Return (version, prefixlen, network int, address int) or None."""
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None
    version = network.version
    return (
        version,
        network.prefixlen,
        _network_int(version, network.network_address.packed),
        _network_int(version, network.network_address.packed),
    )


def _parse_address(text: str) -> tuple[int, int] | None:
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        return None
    return parsed.version, _network_int(parsed.version, parsed.packed)


def _usable_interface(name: str, iface_type: str, family: int, prefixlen: int | None, address: str) -> bool:
    if not address or prefixlen is None or family not in (4, 6):
        return False
    lowered = name.lower()
    if lowered in LOOPBACK_NAME or iface_type.lower().startswith("loopback"):
        return False
    if family == 4 and prefixlen >= 32:
        return False
    if family == 6 and prefixlen >= 128:
        return False
    return True


def _is_virtual(name: str) -> bool:
    return name.lower().startswith(VIRTUAL_PREFIXES)


def _is_tunnel(name: str, iface_type: str) -> bool:
    lowered = name.lower()
    return lowered.startswith(("tun", "wg", "ppp")) or "tunnel" in iface_type.lower()


def _zone_type(hub: _Network) -> str:
    if hub.assumed:
        return "assumed"
    if hub.tunnel:
        return "tunnel"
    if hub.virtual:
        return "virtual"
    return "segment"


def _load_hosts(conn: sqlite3.Connection, engagement_id: str) -> list[_Host]:
    latest_sql = """
        SELECT h.* FROM host_observations h
        WHERE h.id = (
            SELECT h2.id FROM host_observations h2
            WHERE h2.device_id = h.device_id
            ORDER BY h2.observed_at DESC, h2.id DESC LIMIT 1
        )
    """
    rows = conn.execute(
        f"""
        WITH latest AS ({latest_sql})
        SELECT tn.id AS node_id, l.device_id AS device_id, l.reason AS reason,
               l.reason_ttl AS reason_ttl, l.mac AS mac
        FROM topology_nodes tn
        JOIN latest l ON l.device_id = tn.entity_id
        WHERE tn.engagement_id = ? AND tn.kind = 'device'
        """,
        (engagement_id,),
    ).fetchall()
    addresses: dict[str, list[tuple[int, int]]] = {}
    for row in conn.execute(
        f"""
        WITH latest AS ({latest_sql})
        SELECT oa.host_observation_id AS observation_id, a.normalized_value AS value
        FROM observation_addresses oa
        JOIN addresses a ON a.id = oa.address_id
        JOIN latest l ON l.id = oa.host_observation_id
        WHERE a.kind IN ('ipv4', 'ipv6')
        """
    ):
        parsed = _parse_address(str(row["value"]))
        if parsed is not None:
            addresses.setdefault(str(row["observation_id"]), []).append(parsed)

    # Observations are keyed by device, so map device -> latest observation id
    # once rather than querying per host.
    observation_ids = {
        str(row["device_id"]): str(row["observation_id"])
        for row in conn.execute(
            f"WITH latest AS ({latest_sql}) SELECT l.id AS observation_id, l.device_id AS device_id FROM latest l"
        )
    }
    hosts: list[_Host] = []
    for row in rows:
        values = tuple(sorted(set(addresses.get(observation_ids.get(str(row["device_id"]), ""), ()))))
        if not values:
            continue
        hosts.append(
            _Host(
                node_id=str(row["node_id"]),
                device_id=str(row["device_id"]),
                addresses=values,
                reason=str(row["reason"] or ""),
                reason_ttl=row["reason_ttl"],
                mac=str(row["mac"] or ""),
            )
        )
    return hosts


def _observed_pairs(conn: sqlite3.Connection) -> set[tuple[str, str]]:
    """(vantage_point_id, destination_node_id) pairs with a real traced path."""
    rows = conn.execute(
        """
        SELECT tp.vantage_point_id AS vantage_id, tp.destination_node_id AS node_id
        FROM trace_paths tp
        JOIN trace_hops th ON th.trace_path_id = tp.id
        GROUP BY tp.id
        HAVING COUNT(*) > 1
        """
    ).fetchall()
    return {(str(row["vantage_id"]), str(row["node_id"])) for row in rows}


def _latest_decisions(conn: sqlite3.Connection) -> dict[str, str]:
    rows = conn.execute(
        """
        SELECT d.edge_id AS edge_id, d.decision AS decision
        FROM edge_decisions d
        WHERE d.created_at = (SELECT MAX(d2.created_at) FROM edge_decisions d2 WHERE d2.edge_id = d.edge_id)
        """
    ).fetchall()
    return {str(row["edge_id"]): str(row["decision"]) for row in rows}


class _HubIndex:
    """Longest-prefix lookups over hubs, using integer masks only."""

    def __init__(self) -> None:
        self._by_key: dict[tuple[int, int, int], _Network] = {}

    def add(self, network: _Network) -> None:
        self._by_key[network.key] = network

    def find(self, address: int, version: int) -> _Network | None:
        best: _Network | None = None
        for (_, prefixlen, _), network in self._by_key.items():
            if network.version != version:
                continue
            if network.contains(address) and (best is None or prefixlen > best.prefixlen):
                best = network
        return best

    def values(self) -> list[_Network]:
        return list(self._by_key.values())


def _ensure_network(conn: sqlite3.Connection, uid: str, engagement_id: str, cidr: str, version: int, now: str) -> str:
    row = conn.execute(
        "SELECT id FROM networks WHERE engagement_id = ? AND cidr = ? LIMIT 1", (engagement_id, cidr)
    ).fetchone()
    if row is not None:
        return str(row[0])
    network_id = ids.network_id(uid, cidr)
    conn.execute(
        "INSERT INTO networks(id, engagement_id, name, cidr, family, notes, created_at) "
        "VALUES (?, ?, ?, ?, ?, 'derived by inference', ?) ON CONFLICT DO NOTHING",
        (network_id, engagement_id, cidr, cidr, version, now),
    )
    row = conn.execute(
        "SELECT id FROM networks WHERE engagement_id = ? AND name = ?", (engagement_id, cidr)
    ).fetchone()
    return str(row[0]) if row is not None else network_id


def _hub(
    conn: sqlite3.Connection,
    uid: str,
    engagement_id: str,
    plan: _Plan,
    cidr: str,
    *,
    assumed: bool = False,
    virtual: bool = False,
    tunnel: bool = False,
    iface: str = "",
    now: str,
) -> _Network:
    parsed = _parse_cidr(cidr)
    if parsed is None:
        raise ValueError(f"Invalid CIDR for a hub: {cidr!r}")
    version, prefixlen, network, _ = parsed
    key = (version, prefixlen, network)
    existing = plan.hubs.get(key)
    if existing is not None:
        return existing
    canonical = str(ipaddress.ip_network(cidr, strict=False))
    network_id = _ensure_network(conn, uid, engagement_id, canonical, version, now)
    zone_id = ids.zone_id(uid, network_id, canonical)
    node_id = ids.node_id(uid, "zone", zone_id)
    label = f"~{canonical}" if assumed else canonical
    conn.execute(
        "INSERT INTO zones(id, engagement_id, name, zone_type, description, author, created_at, "
        "derived, cidr, network_id) VALUES (?, ?, ?, ?, '', 'lumos', ?, 1, ?, ?) "
        "ON CONFLICT DO NOTHING",
        (zone_id, engagement_id, label, _zone_type(_Network(key, canonical, version, prefixlen, network,
                                                           assumed=assumed, virtual=virtual, tunnel=tunnel)),
         now, canonical, network_id),
    )
    conn.execute(
        "INSERT INTO topology_nodes(id, engagement_id, kind, entity_id, label, created_at) "
        "VALUES (?, ?, 'zone', ?, ?, ?) ON CONFLICT DO NOTHING",
        (node_id, engagement_id, zone_id, label, now),
    )
    hub = _Network(
        key=key,
        cidr=canonical,
        version=version,
        prefixlen=prefixlen,
        network=network,
        zone_id=zone_id,
        node_id=node_id,
        assumed=assumed,
        virtual=virtual,
        tunnel=tunnel,
        iface=iface,
    )
    plan.hubs[key] = hub
    return hub


def _add_edge(
    plan: _Plan,
    from_node: str,
    to_node: str,
    *,
    edge_type: str,
    rule: str,
    confidence: float,
    evidence: dict,
) -> None:
    if from_node == to_node:
        return
    plan.edges.append(
        (
            from_node,
            to_node,
            edge_type,
            confidence,
            {"rule": rule, "rule_version": RULE_VERSION, **evidence},
        )
    )


def _route_rows(conn: sqlite3.Connection, vantage_id: str) -> list[sqlite3.Row]:
    return conn.execute(
        "SELECT dst_cidr AS dst_cidr, dev AS dev, metric AS metric, gateway AS gateway "
        "FROM vantage_routes WHERE vantage_point_id = ?",
        (vantage_id,),
    ).fetchall()


def _plan_vantage(
    conn: sqlite3.Connection,
    uid: str,
    engagement_id: str,
    vantage_id: str,
    hosts: list[_Host],
    observed: set[tuple[str, str]],
    plan: _Plan,
    now: str,
) -> None:
    root = conn.execute(
        "SELECT id FROM topology_nodes WHERE engagement_id = ? AND kind = 'root' AND entity_id = ?",
        (engagement_id, vantage_id),
    ).fetchone()
    if root is None:
        return
    root_id = str(root[0])

    interfaces = conn.execute(
        "SELECT name, address, mac, is_up, prefix_len, family, iface_type "
        "FROM vantage_interfaces WHERE vantage_point_id = ? AND is_up = 1",
        (vantage_id,),
    ).fetchall()
    connected = _HubIndex()
    gateway_routes: list[tuple[int, int, int, sqlite3.Row]] = []
    default_gateway: sqlite3.Row | None = None
    for row in interfaces:
        parsed = _parse_address(str(row["address"]).split("/", 1)[0])
        if parsed is None or not _usable_interface(
            str(row["name"]), str(row["iface_type"]), int(row["family"]), row["prefix_len"], str(row["address"])
        ):
            continue
        version, address_int = parsed
        prefixlen = int(row["prefix_len"] or (24 if version == 4 else 64))
        network_int = address_int & _mask(version, prefixlen)
        network = _Network(
            key=(version, prefixlen, network_int),
            cidr=str(ipaddress.ip_network(f"{ipaddress.ip_address(address_int)}/{prefixlen}", strict=False)),
            version=version,
            prefixlen=prefixlen,
            network=network_int,
            virtual=_is_virtual(str(row["name"])),
            tunnel=_is_tunnel(str(row["name"]), str(row["iface_type"])),
        )
        hub = _hub(conn, uid, engagement_id, plan, network.cidr,
                   virtual=network.virtual, tunnel=network.tunnel, iface=str(row["name"]), now=now)
        connected.add(hub)
        _add_edge(
            plan, root_id, hub.node_id, edge_type="local", rule=LOCAL_INTERFACE, confidence=CONFIDENCE[LOCAL_INTERFACE],
            evidence={"interface": str(row["name"]), "address": str(row["address"]), "vantage_id": vantage_id},
        )

    user_networks = _HubIndex()
    for row in conn.execute(
        "SELECT id, cidr FROM networks WHERE engagement_id = ? AND cidr IS NOT NULL AND cidr <> ''",
        (engagement_id,),
    ):
        parsed_network = _parse_cidr(str(row["cidr"]))
        if parsed_network is None:
            continue
        version, prefixlen, network, _ = parsed_network
        user_networks.add(
            _Network(
                key=(version, prefixlen, network),
                cidr=str(ipaddress.ip_network(str(row["cidr"]), strict=False)),
                version=version,
                prefixlen=prefixlen,
                network=network,
            )
        )

    for row in _route_rows(conn, vantage_id):
        if str(row["dst_cidr"]).lower() == "default":
            default_gateway = row
            continue
        parsed = _parse_cidr(str(row["dst_cidr"]))
        if parsed is None:
            continue
        version, prefixlen, network, _ = parsed
        if version == 4 and prefixlen == 0:
            default_gateway = row
            continue
        if row["gateway"]:
            gateway_routes.append((version, prefixlen, network, row))
    gateway_routes.sort(key=lambda item: (-item[1], int(item[3]["metric"])))

    # Host nodes by address, for gateway promotion ("the scanned device if it exists").
    by_address: dict[tuple[int, int], _Host] = {}
    for host in hosts:
        for version, address in host.addresses:
            by_address.setdefault((version, address), host)

    placeholder_nodes: dict[tuple[int, int], str] = {}

    def gateway_node(gateway: str) -> str:
        parsed_address = _parse_address(gateway)
        if parsed_address is None:
            raise ValueError(f"Invalid gateway address: {gateway!r}")
        host = by_address.get(parsed_address)
        if host is not None:
            return host.node_id
        existing = placeholder_nodes.get(parsed_address)
        if existing is not None:
            return existing
        key = f"gateway:{gateway}"
        conn.execute(
            "INSERT INTO topology_nodes(id, engagement_id, kind, entity_id, label, created_at) "
            "VALUES (?, ?, 'unknown_hop', ?, ?, ?) ON CONFLICT DO NOTHING",
            (ids.node_id(uid, "unknown_hop", key), engagement_id, key, gateway, now),
        )
        placeholder_nodes[parsed_address] = ids.node_id(uid, "unknown_hop", key)
        return placeholder_nodes[parsed_address]

    # Proxy ARP: many addresses sharing one MAC is a router answering for all of
    # them, so those on-link claims are downgraded to address evidence.
    mac_counts: dict[str, int] = {}
    for host in hosts:
        if host.mac and host.reason.lower() in ARP_REASONS:
            mac_counts[host.mac.lower()] = mac_counts.get(host.mac.lower(), 0) + 1
    suspicious = {mac for mac, count in mac_counts.items() if count >= PROXY_ARP_THRESHOLD}
    for mac in sorted(suspicious):
        _review_mac(conn, uid, engagement_id, vantage_id, mac, mac_counts[mac], now)

    for host in hosts:
        primary = next(((v, a) for v, a in host.addresses if v == 4), host.addresses[0])
        version, address = primary
        hub = connected.find(address, version)
        route: tuple[int, int, int, sqlite3.Row] | None = None
        assumed_route = False
        matched_user_network = False
        if hub is None:
            route = next(
                (
                    item
                    for item in gateway_routes
                    if item[0] == version and (address & _mask(version, item[1])) == item[2]
                ),
                None,
            )
            if route is not None:
                hub = _hub(conn, uid, engagement_id, plan, str(route[3]["dst_cidr"]), now=now)
            elif default_gateway is not None and str(default_gateway["gateway"]):
                # The default route supplies the next hop but not the prefix.
                # Prefer a network the user declared; otherwise assume /24 or /64.
                route = (version, 0, 0, default_gateway)
                declared = user_networks.find(address, version)
                if declared is not None:
                    hub = _hub(conn, uid, engagement_id, plan, declared.cidr, now=now)
                    matched_user_network = True
                else:
                    assumed_prefix = 24 if version == 4 else 64
                    assumed_cidr = str(
                        ipaddress.ip_network(
                            f"{ipaddress.ip_address(address & _mask(version, assumed_prefix))}/{assumed_prefix}",
                            strict=False,
                        )
                    )
                    hub = _hub(conn, uid, engagement_id, plan, assumed_cidr, assumed=True, now=now)
                    assumed_route = True

        if hub is None:
            assumed_prefix = 24 if version == 4 else 64
            assumed_cidr = str(
                ipaddress.ip_network(
                    f"{ipaddress.ip_address(address & _mask(version, assumed_prefix))}/{assumed_prefix}",
                    strict=False,
                )
            )
            hub = _hub(conn, uid, engagement_id, plan, assumed_cidr, assumed=True, now=now)

        # Grouping is not connectivity: membership is recorded even when the
        # host's link is observed and therefore not inferred.
        plan.memberships.append((hub.zone_id, host.node_id))
        if (vantage_id, host.node_id) in observed:
            continue

        if route is None and not hub.assumed:
            arp = (
                host.reason.lower() in ARP_REASONS
                and bool(host.mac)
                and not hub.tunnel
                and host.mac.lower() not in suspicious
            )
            rule = ON_LINK_ARP if arp else ON_LINK_ADDRESS
            _add_edge(
                plan, hub.node_id, host.node_id, edge_type="inferred", rule=rule, confidence=CONFIDENCE[rule],
                evidence={
                    "address": str(ipaddress.ip_address(address)),
                    "cidr": hub.cidr,
                    "interface": hub.iface,
                    "reason": host.reason,
                    "reason_ttl": host.reason_ttl,
                    "mac": host.mac,
                    "hardware_addressed": arp,
                },
            )
            continue

        if route is not None:
            gateway = str(route[3]["gateway"])
            gateway_host = gateway_node(gateway)
            gateway_parsed = _parse_address(gateway)
            gateway_hub = connected.find(gateway_parsed[1], gateway_parsed[0]) if gateway_parsed else None
            if gateway_hub is not None:
                _add_edge(
                    plan, gateway_hub.node_id, gateway_host, edge_type="inferred", rule=GATEWAY_ON_LINK,
                    confidence=CONFIDENCE[GATEWAY_ON_LINK],
                    evidence={
                        "gateway": gateway,
                        "cidr": gateway_hub.cidr,
                        "route": str(route[3]["dst_cidr"]),
                        "device_scanned": gateway_parsed in by_address if gateway_parsed else False,
                    },
                )
            _add_edge(
                plan, gateway_host, hub.node_id, edge_type="inferred", rule=ROUTED_VIA_GATEWAY,
                confidence=CONFIDENCE["routed_hub"],
                evidence={
                    "gateway": gateway,
                    "cidr": str(route[3]["dst_cidr"]),
                    "route": str(route[3]["dst_cidr"]),
                    "metric": int(route[3]["metric"]),
                },
            )
            supplied = route[1] > 0 or matched_user_network
            host_confidence = CONFIDENCE[ROUTED_VIA_GATEWAY] if supplied else CONFIDENCE["routed_via_gateway_assumed"]
            _add_edge(
                plan, hub.node_id, host.node_id, edge_type="inferred", rule=ROUTED_VIA_GATEWAY,
                confidence=host_confidence,
                evidence={
                    "address": str(ipaddress.ip_address(address)),
                    "cidr": hub.cidr,
                    "gateway": gateway,
                    "assumed_prefix": not supplied,
                },
            )
            continue

        # Neither an interface nor any route: explicitly weak and labelled.
        conn.execute(
            "UPDATE topology_nodes SET label = 'path unknown' WHERE id = ?", (hub.node_id,)
        )
        conn.execute("UPDATE zones SET name = 'path unknown' WHERE id = ?", (hub.zone_id,))
        _add_edge(
            plan, root_id, hub.node_id, edge_type="inferred", rule=UNKNOWN_PATH,
            confidence=CONFIDENCE["unknown_path_hub"],
            evidence={"hub": hub.cidr, "vantage_id": vantage_id, "reason": "no interface or route data"},
        )
        _add_edge(
            plan, hub.node_id, host.node_id, edge_type="inferred", rule=UNKNOWN_PATH,
            confidence=CONFIDENCE["unknown_path_host"],
            evidence={"address": str(ipaddress.ip_address(address)), "cidr": hub.cidr, "assumed_prefix": True},
        )


def _review_mac(conn, uid: str, engagement_id: str, vantage_id: str, mac: str, count: int, now: str) -> None:
    item_id = ids.review_item_id(uid, "mac", mac, "proxy_arp_suspected")
    conn.execute(
        "INSERT INTO review_items(id, engagement_id, target_kind, target_id, reason_code, reason_detail, "
        "created_at, latest_event_at) VALUES (?, ?, 'mac', ?, 'proxy_arp_suspected', ?, ?, ?) "
        "ON CONFLICT DO NOTHING",
        (
            item_id,
            engagement_id,
            mac,
            sanitize_text(
                f"{count} addresses answered ARP with MAC {mac} on vantage {vantage_id}; "
                "treat on-link claims with suspicion.",
                max_chars=4096,
            ),
            now,
            now,
        ),
    )


def rebuild_inferred(database: str | Path, *, now: str | None = None) -> RebuildStats:
    """Rebuild every derived hub, link and membership from stored facts."""
    conn = open_database(database, readonly=False)
    try:
        with conn:
            return _rebuild(conn, now=now)
    finally:
        conn.close()


def _rebuild(conn: sqlite3.Connection, *, now: str | None = None) -> RebuildStats:
    stamp = now or utc_now()
    engagement = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()
    if engagement is None:
        raise ValueError("Database has no engagement")
    engagement_id = str(engagement[0])
    uid = ids.ensure_engagement_uid(conn)
    hosts = _load_hosts(conn, engagement_id)
    observed = _observed_pairs(conn)
    decisions = _latest_decisions(conn)

    plan = _Plan()
    vantages = [
        str(row[0])
        for row in conn.execute("SELECT id FROM vantage_points WHERE engagement_id = ?", (engagement_id,))
    ]
    for vantage_id in vantages:
        _plan_vantage(conn, uid, engagement_id, vantage_id, hosts, observed, plan, stamp)

    # Apply user decisions: rejected links never come back, promoted ones were
    # materialised as manual edges when the user made the decision.
    kept_edges: set[str] = set()
    for from_node, to_node, edge_type, confidence, evidence in plan.edges:
        rule = str(evidence["rule"])
        edge_id = (
            ids.inferred_edge_id(uid, from_node, to_node, rule)
            if edge_type == "inferred"
            else ids.edge_id(uid, from_node, to_node, edge_type, f"rule:{rule}")
        )
        if decisions.get(edge_id) == "rejected":
            continue
        if decisions.get(edge_id) == "promoted":
            continue
        kept_edges.add(edge_id)
        conn.execute(
            "INSERT INTO topology_edges(id, engagement_id, from_node_id, to_node_id, edge_type, source_kind, "
            "source_id, confidence, first_observed_at, last_confirmed_at, derived, evidence_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?) "
            "ON CONFLICT(id) DO UPDATE SET confidence = excluded.confidence, "
            "last_confirmed_at = excluded.last_confirmed_at, evidence_json = excluded.evidence_json",
            (
                edge_id,
                engagement_id,
                from_node,
                to_node,
                edge_type,
                f"rule:{rule}",
                None,
                confidence,
                stamp,
                stamp,
                json.dumps(evidence, ensure_ascii=False, sort_keys=True),
            ),
        )
    removed_edges = _prune(conn, "topology_edges", engagement_id, kept_edges, "derived = 1")

    kept_hubs = {hub.zone_id for hub in plan.hubs.values()}
    for zone_id, node_id in plan.memberships:
        conn.execute(
            "INSERT INTO zone_memberships(zone_id, topology_node_id, author, created_at) "
            "VALUES (?, ?, 'lumos', ?) ON CONFLICT DO NOTHING",
            (zone_id, node_id, stamp),
        )
    if kept_hubs:
        placeholders = ",".join("?" for _ in kept_hubs)
        conn.execute(
            f"DELETE FROM zone_memberships WHERE author = 'lumos' AND zone_id NOT IN ({placeholders})",
            tuple(kept_hubs),
        )
    else:
        conn.execute("DELETE FROM zone_memberships WHERE author = 'lumos'")
    removed_hubs = _prune_hubs(conn, engagement_id, kept_hubs)

    return RebuildStats(
        hubs=len(plan.hubs),
        edges=len(kept_edges),
        local_edges=sum(1 for _, _, kind, _, _ in plan.edges if kind == "local"),
        memberships=len(plan.memberships),
        removed_edges=removed_edges,
        removed_hubs=removed_hubs,
        review_items=len(
            conn.execute(
                "SELECT COUNT(*) FROM review_items WHERE reason_code = 'proxy_arp_suspected'"
            ).fetchone()
        ),
    )


def _prune(conn: sqlite3.Connection, table: str, engagement_id: str, keep: set[str], extra: str) -> int:
    conn.execute("CREATE TEMP TABLE IF NOT EXISTS rebuild_keep(id TEXT PRIMARY KEY)")
    conn.execute("DELETE FROM rebuild_keep")
    conn.executemany("INSERT OR IGNORE INTO rebuild_keep(id) VALUES (?)", ((value,) for value in keep))
    before = conn.execute(
        f"SELECT COUNT(*) FROM {table} WHERE engagement_id = ? AND {extra}", (engagement_id,)
    ).fetchone()[0]
    conn.execute(
        f"DELETE FROM {table} WHERE engagement_id = ? AND {extra} "
        "AND id NOT IN (SELECT id FROM rebuild_keep)",
        (engagement_id,),
    )
    after = conn.execute(
        f"SELECT COUNT(*) FROM {table} WHERE engagement_id = ? AND {extra}", (engagement_id,)
    ).fetchone()[0]
    return max(0, int(before) - int(after))


def _prune_hubs(conn: sqlite3.Connection, engagement_id: str, keep: set[str]) -> int:
    rows = conn.execute(
        "SELECT id FROM zones WHERE engagement_id = ? AND derived = 1", (engagement_id,)
    ).fetchall()
    stale = [str(row[0]) for row in rows if str(row[0]) not in keep]
    for zone_id in stale:
        node = conn.execute(
            "SELECT id FROM topology_nodes WHERE engagement_id = ? AND kind = 'zone' AND entity_id = ?",
            (engagement_id, zone_id),
        ).fetchone()
        if node is not None:
            conn.execute("DELETE FROM topology_nodes WHERE id = ?", (node[0],))
        conn.execute("DELETE FROM zones WHERE id = ?", (zone_id,))
    return len(stale)
