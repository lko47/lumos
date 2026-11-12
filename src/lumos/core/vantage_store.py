"""Record the local scanner's interfaces on the engagement's vantage point."""

from __future__ import annotations

import socket
import uuid
from pathlib import Path

from . import ids
from .database import open_database, utc_now
from .nmap.iflist import InterfaceSnapshot
from .text import sanitize_text
from .topology_store import ensure_node

MAX_INTERFACES = 64


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
            conn.execute("DELETE FROM vantage_interfaces WHERE vantage_point_id = ?", (vantage_id,))
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
            saved = 0
            for item in snapshot.interfaces:
                interface_name = sanitize_text(item.name, max_chars=64).strip()
                if not interface_name:
                    continue
                conn.execute(
                    "INSERT INTO vantage_interfaces(id, vantage_point_id, name, address, mac, is_up, captured_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (
                        str(uuid.uuid4()),
                        vantage_id,
                        interface_name,
                        sanitize_text(item.address or "", max_chars=128),
                        sanitize_text(item.mac or "", max_chars=64),
                        int(bool(item.is_up)),
                        now,
                    ),
                )
                saved += 1
        return vantage_id, saved
    finally:
        conn.close()
