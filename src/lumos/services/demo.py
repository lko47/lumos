"""A synthetic engagement, generated through the same writer a scan uses.

The demo exists so screenshots, docs and manual testing never touch a real
network. Every value here is invented: documentation-range addresses,
``.example`` hostnames and locally-administered MACs. Nothing is imported from
an engagement.

It is built with :class:`ScanWriter` - the writer a real Nmap run feeds - and
then the inference pass, so the demo exercises the same code path as a scan
instead of inserting a plausible-looking database shape by hand.
"""

from __future__ import annotations

import hashlib
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path

from ..core.database import initialize_database, open_database
from ..core.inference import rebuild_inferred
from ..core.nmap.iflist import InterfaceEntry, InterfaceSnapshot, RouteEntry
from ..core.nmap.xml_stream import AddressRecord, HostRecord, PortRecord
from ..core.vantage_store import save_interfaces
from ..core.scan_store import ScanWriter, make_scan_context
from . import notes, tags

DEMO_NAME = "Lumos demo engagement"
DEMO_OPERATOR = "demo"

Networks = tuple[tuple[str, str], ...]
NETWORKS: Networks = (
    ("office", "192.0.2.0/24"),
    ("dmz", "198.51.100.0/24"),
    ("lab", "203.0.113.0/24"),
)

Host = tuple[str, str, str, tuple[tuple[int, str, str, str], ...]]
# (address, hostname, os, ((port, service, product, version), ...))
HOSTS: dict[str, tuple[Host, ...]] = {
    "office": (
        ("192.0.2.1", "gw-01.example", "Linux 5.x", (
            (22, "ssh", "OpenSSH", "9.6"),
            (53, "domain", "dnsmasq", "2.90"),
        )),
        ("192.0.2.14", "ws-07.example", "Windows 11", (
            (135, "msrpc", "Microsoft Windows RPC", ""),
            (445, "microsoft-ds", "", ""),
        )),
        ("192.0.2.19", "ws-08.example", "Windows 11", (
            (445, "microsoft-ds", "", ""),
            (3389, "ms-wbt-server", "Microsoft Terminal Services", ""),
        )),
        ("192.0.2.31", "printer-01.example", "embedded", (
            (80, "http", "HP embedded web server", ""),
            (9100, "jetdirect", "", ""),
        )),
    ),
    "dmz": (
        ("198.51.100.10", "web-01.example", "Linux 5.x", (
            (80, "http", "nginx", "1.26.1"),
            (443, "https", "nginx", "1.26.1"),
        )),
        ("198.51.100.25", "mail-01.example", "Linux 5.x", (
            (25, "smtp", "Postfix smtpd", ""),
            (993, "imaps", "Dovecot", "2.3.21"),
        )),
    ),
    "lab": (
        ("203.0.113.7", "build-01.example", "Linux 6.x", (
            (22, "ssh", "OpenSSH", "9.7"),
            (8080, "http-proxy", "Jenkins", "2.452"),
        )),
        ("203.0.113.20", "nas-01.example", "Linux 5.x", (
            (139, "netbios-ssn", "Samba", "4.20"),
            (445, "microsoft-ds", "Samba", "4.20"),
        )),
        ("203.0.113.33", "kvm-01.example", "Linux 6.x", (
            (22, "ssh", "OpenSSH", "9.7"),
            (5900, "vnc", "QEMU VNC", ""),
        )),
    ),
}

# The follow-up is a targeted rescan of two hosts, not a second sweep of the
# whole network: Lumos deliberately does not auto-merge device identity across
# scans, so re-sweeping everything would triple the map with duplicates.
ROUND_TWO: tuple[tuple[str, Host, tuple[int, ...]], ...] = (
    ("office", ("192.0.2.44", "ws-11.example", "Windows 11", (
        (135, "msrpc", "Microsoft Windows RPC", ""),
    )), ()),
    ("office", ("192.0.2.19", "ws-08.example", "Windows 11", (
        (445, "microsoft-ds", "", ""),
        (3389, "ms-wbt-server", "Microsoft Terminal Services", ""),
    )), (445,)),
)
CLOSED_PORTS: dict[str, tuple[int, ...]] = {"192.0.2.19": (445,)}


class DemoError(ValueError):
    """A demo database that cannot be written, with the reason in the sentence."""


@dataclass(frozen=True)
class DemoStats:
    path: Path
    hosts: int
    scans: int
    nodes: int
    edges: int
    zones: int


def _insert_networks(conn: sqlite3.Connection, engagement_id: str, now: str) -> dict[str, str]:
    ids: dict[str, str] = {}
    for name, cidr in NETWORKS:
        network_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO networks (id, engagement_id, name, cidr, created_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (network_id, engagement_id, name, cidr, now),
        )
        ids[name] = network_id
    return ids


def _demo_mac(address: str) -> str:
    """A stable, obviously-fake MAC per demo host, so rounds keep one device."""
    digest = hashlib.sha256(address.encode()).digest()
    return "02:00:" + ":".join(f"{byte:02x}" for byte in digest[:4])


def _host_record(host: Host, *, closed: tuple[int, ...] = ()) -> HostRecord:
    address, hostname, os_name, ports = host
    records = tuple(
        PortRecord(
            protocol="tcp",
            port=port,
            state="closed" if port in closed else "open",
            reason="syn-ack" if port not in closed else "reset",
            service=service,
            product=product,
            version=version,
        )
        for port, service, product, version in ports
    )
    return HostRecord(
        state="up",
        reason="arp-response",
        addresses=(
            AddressRecord(kind="ipv4", value=address),
            AddressRecord(kind="mac", value=_demo_mac(address)),
        ),
        hostnames=(hostname,) if hostname else (),
        os_name=os_name,
        os_accuracy=95 if os_name else None,
        ports=records,
        scripts=(),
        hops=(),
    )


def _demo_interfaces() -> InterfaceSnapshot:
    """Three connected interfaces, so the map labels zones instead of guessing."""
    entries = tuple(
        InterfaceEntry(
            name=f"demo{index}",
            short_name=f"dm{index}",
            address=f"{cidr.split('.')[0]}.{cidr.split('.')[1]}.{cidr.split('.')[2]}.10",
            interface_type="ethernet",
            is_up=True,
            mtu=1500,
            mac=f"02:00:00:00:0{index}:01",
            prefix_len=24,
            family=4,
        )
        for index, (_name, cidr) in enumerate(NETWORKS)
    )
    routes = tuple(
        RouteEntry(destination=cidr, device=f"demo{index}", metric=0, gateway=None)
        for index, (_name, cidr) in enumerate(NETWORKS)
    )
    return InterfaceSnapshot(interfaces=entries, routes=routes)


def _write_scan(
    database: Path,
    network_name: str,
    hosts: tuple[Host, ...],
    *,
    target: str,
    started_at: str,
    closed: dict[str, tuple[int, ...]] | None = None,
) -> None:
    conn = open_database(database, readonly=True)
    try:
        engagement_id = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()[0]
        network_id = conn.execute(
            "SELECT id FROM networks WHERE name = ?", (network_name,)
        ).fetchone()[0]
    finally:
        conn.close()
    context = make_scan_context(
        engagement_id=str(engagement_id),
        network_id=str(network_id),
        targets=[target],
        resolved_targets=[target],
        argv=["nmap", "-sT", "-sV", "-oX", "-", target],
        nmap_version="7.99 (demo)",
        scanner_name="demo-scanner",
        operator=DEMO_OPERATOR,
        interface="demo0",
        scope_override=False,
        evidence_enabled=False,
    )
    context["started_at"] = started_at
    context["engagement_uid"] = str(engagement_id)
    context["iflist"] = _demo_interfaces()
    writer = ScanWriter(database, context)
    closed = closed or {}
    for host in hosts:
        writer.submit_host(_host_record(host, closed=closed.get(host[0], ())))
    writer.finish(
        exit_code=0,
        status="completed",
        evidence=None,
        evidence_bytes=0,
        evidence_sha256="",
        detail="",
    )


def _decorate(database: Path) -> None:
    """A note, a pair of tags and one review decision, so the panels have content."""
    conn = open_database(database, readonly=True)
    try:
        node = conn.execute(
            "SELECT id FROM topology_nodes WHERE kind = 'device' ORDER BY label LIMIT 1"
        ).fetchone()
        root = conn.execute("SELECT id FROM topology_nodes WHERE kind = 'root' LIMIT 1").fetchone()
        item = conn.execute("SELECT id FROM review_items LIMIT 1").fetchone()
    finally:
        conn.close()
    if node is not None:
        notes.add_note(
            database,
            target_kind="topology_node",
            target_id=str(node[0]),
            body="Generated example: the build host answers SSH and a Jenkins UI.",
            author=DEMO_OPERATOR,
        )
        tags.add_tag(
            database, object_kind="topology_node", object_id=str(node[0]),
            name="lab", author=DEMO_OPERATOR,
        )
    if root is not None:
        tags.add_tag(
            database, object_kind="topology_node", object_id=str(root[0]),
            name="vantage", author=DEMO_OPERATOR,
        )
    if item is not None:
        from . import review

        review.set_state(
            database, str(item[0]), "confirmed",
            author=DEMO_OPERATOR, detail="example decision",
        )


def build_demo(path: str | Path, *, overwrite: bool = False) -> DemoStats:
    """Write a self-contained demo engagement and return what it contains."""
    target = Path(path)
    if target.exists():
        if not overwrite:
            raise DemoError(f"{target} exists; pass overwrite to replace it")
        target.unlink()
    target.parent.mkdir(parents=True, exist_ok=True)
    initialize_database(target, DEMO_NAME)

    conn = open_database(target)
    try:
        with conn:
            engagement_id = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()[0]
            conn.execute(
                "UPDATE engagement SET operator = ? WHERE id = ?",
                (DEMO_OPERATOR, engagement_id),
            )
            _insert_networks(conn, str(engagement_id), "2026-01-01T00:00:00Z")
    finally:
        conn.close()
    save_interfaces(target, _demo_interfaces(), scanner_name="demo-scanner", operator=DEMO_OPERATOR)

    for index, (network, hosts) in enumerate(HOSTS.items()):
        cidr = dict(NETWORKS)[network]
        _write_scan(
            target, network, hosts,
            target=cidr, started_at=f"2026-01-01T0{index + 1}:00:00.000000Z",
        )
    for index, (network, host, closed_ports) in enumerate(ROUND_TWO):
        cidr = dict(NETWORKS)[network]
        _write_scan(
            target, network, (host,),
            target=f"{host[0]}/32", started_at=f"2026-02-01T0{index + 1}:00:00.000000Z",
            closed={host[0]: closed_ports} if closed_ports else {},
        )

    rebuild_inferred(target)
    _decorate(target)

    conn = open_database(target, readonly=True)
    try:
        counts = {
            "hosts": conn.execute("SELECT COUNT(*) FROM devices").fetchone()[0],
            "scans": conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
            "nodes": conn.execute("SELECT COUNT(*) FROM topology_nodes").fetchone()[0],
            "edges": conn.execute("SELECT COUNT(*) FROM topology_edges").fetchone()[0],
            "zones": conn.execute("SELECT COUNT(*) FROM zones").fetchone()[0],
        }
    finally:
        conn.close()
    try:
        target.chmod(0o600)
    except OSError:
        pass
    return DemoStats(path=target, **counts)