"""Record the local scanner's interfaces on the engagement's vantage point."""

from __future__ import annotations

import socket
from pathlib import Path

from . import ids
from .database import open_database, utc_now
from .nmap.iflist import InterfaceSnapshot
from .text import sanitize_text
from .topology_store import ensure_node

MAX_INTERFACES = 64
MAX_ROUTES = 256



def count_interfaces(conn, vantage_id: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM vantage_interfaces WHERE vantage_point_id = ?", (vantage_id,)
    ).fetchone()
    return int(row[0]) if row else 0


def write_snapshot(conn, engagement_uid: str, vantage_id: str, snapshot: InterfaceSnapshot, captured_at: str) -> None:
    """Replace one vantage point's interfaces and routes with a fresh capture.

    The scan writer calls this at the start of every scan, so the routes always
    match the network the scanner was actually attached to.
    """
    if len(snapshot.interfaces) > MAX_INTERFACES:
        raise VantageStoreError(f"Refusing to save more than {MAX_INTERFACES} interfaces")
    if len(snapshot.routes) > MAX_ROUTES:
        raise VantageStoreError(f"Refusing to save more than {MAX_ROUTES} routes")
    conn.execute("DELETE FROM vantage_interfaces WHERE vantage_point_id = ?", (vantage_id,))
    conn.execute("DELETE FROM vantage_routes WHERE vantage_point_id = ?", (vantage_id,))
    for item in snapshot.interfaces:
        interface_name = sanitize_text(item.name, max_chars=64).strip()
        if not interface_name:
            continue
        conn.execute(
            "INSERT INTO vantage_interfaces(id, vantage_point_id, name, address, mac, is_up, "
            "captured_at, prefix_len, family, iface_type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(vantage_point_id, name, address) DO NOTHING",
            (
                ids.node_id(engagement_uid, "interface", f"{vantage_id}:{interface_name}:{item.address or ''}"),
                vantage_id,
                interface_name,
                sanitize_text(item.address or "", max_chars=128),
                sanitize_text(item.mac or "", max_chars=64),
                int(bool(item.is_up)),
                captured_at,
                item.prefix_len,
                int(item.family or 0),
                sanitize_text(item.interface_type or "", max_chars=32),
            ),
        )
    for route in snapshot.routes:
        conn.execute(
            "INSERT INTO vantage_routes(id, vantage_point_id, dst_cidr, dev, metric, gateway, captured_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
            (
                ids.vantage_route_id(
                    engagement_uid, vantage_id, route.destination, route.device, route.metric, route.gateway or ""
                ),
                vantage_id,
                sanitize_text(route.destination, max_chars=64),
                sanitize_text(route.device, max_chars=64),
                int(route.metric),
                sanitize_text(route.gateway or "", max_chars=64),
                captured_at,
            ),
        )


class VantageStoreError(ValueError):
    """The interface snapshot could not be stored on the engagement."""


def save_interfaces(
    database: str | Path,
    snapshot: InterfaceSnapshot,
    *,
    scanner_name: str = "",
    operator: str = "",
) -> tuple[str, int]:
    """Replace the saved interfaces for this scanner; return ``(vantage_id, count)``.

    One vantage point per scanner name is reused, matching how scans record
    their origin, so saving again refreshes the list instead of duplicating it.
    """
    name = sanitize_text(scanner_name or socket.gethostname(), max_chars=512).strip()
    if not name:
        raise VantageStoreError("A scanner name is required to save interfaces")
    if len(snapshot.interfaces) > MAX_INTERFACES:
        raise VantageStoreError(f"Refusing to save more than {MAX_INTERFACES} interfaces")

    conn = open_database(database, readonly=False)
    try:
        engagement = conn.execute("SELECT id, operator FROM engagement LIMIT 1").fetchone()
        if engagement is None:
            raise VantageStoreError("The database has no engagement to attach interfaces to")
        engagement_id = engagement[0]
        engagement_uid = ids.ensure_engagement_uid(conn)
        operator_name = sanitize_text(operator or engagement[1] or "", max_chars=256)
        now = utc_now()
        with conn:
            conn.execute(
                "INSERT INTO vantage_points(id, engagement_id, scanner_name, operator, created_at) "
                "VALUES (?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                (ids.vantage_id(engagement_uid, name), engagement_id, name, operator_name, now),
            )
            row = conn.execute(
                "SELECT id FROM vantage_points WHERE engagement_id = ? AND scanner_name = ?",
                (engagement_id, name),
            ).fetchone()
            if row is None:
                raise VantageStoreError("Could not record the vantage point")
            vantage_id = str(row[0])
            write_snapshot(conn, engagement_uid, vantage_id, snapshot, now)
            # The scanner root must exist for the TUI to show a vantage point
            # before any scan has run; scans reuse this same row.
            ensure_node(
                conn,
                engagement_id,
                ids.node_id(engagement_uid, "root", vantage_id),
                "root",
                vantage_id,
                name,
                now,
            )
            saved = count_interfaces(conn, vantage_id)
        return vantage_id, saved
    finally:
        conn.close()
