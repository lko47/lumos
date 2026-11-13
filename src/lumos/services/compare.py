"""Compare two scans: what appeared, what went away, what changed.

A diff is a statement about two observations, not about the network: a host that
vanished may have been filtered, powered off, or seen from a different vantage.
The report says "gone" and carries the scan ids so nobody reads it as truth.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, field
from pathlib import Path

from ..core.database import open_database

ADDED = "added"
REMOVED = "removed"
CHANGED = "changed"
UNCHANGED = "unchanged"


class CompareError(ValueError):
    """A comparison that cannot be made, with the reason in the sentence."""


@dataclass(frozen=True)
class PortLine:
    protocol: str
    port: int
    state: str
    service: str

    @property
    def key(self) -> str:
        return f"{self.protocol}/{self.port}"

    def __str__(self) -> str:
        return f"{self.port}/{self.protocol} {self.state}" + (
            f" {self.service}" if self.service else ""
        )


@dataclass(frozen=True)
class HostChange:
    address: str
    hostname: str
    status: str
    ports_added: tuple[PortLine, ...] = ()
    ports_removed: tuple[PortLine, ...] = ()
    ports_changed: tuple[tuple[PortLine, PortLine], ...] = ()

    @property
    def is_interesting(self) -> bool:
        return bool(self.ports_added or self.ports_removed or self.ports_changed)


@dataclass(frozen=True)
class ScanSummary:
    id: str
    started_at: str
    targets: str


@dataclass(frozen=True)
class ScanDiff:
    left: ScanSummary
    right: ScanSummary
    hosts: tuple[HostChange, ...] = ()
    hosts_per_side: dict[str, int] = field(default_factory=dict)

    def by_status(self, status: str) -> tuple[HostChange, ...]:
        return tuple(host for host in self.hosts if host.status == status)

    @property
    def summary_line(self) -> str:
        return (
            f"{len(self.by_status(ADDED))} added, "
            f"{len(self.by_status(REMOVED))} gone, "
            f"{len(self.by_status(CHANGED))} changed"
        )


def recent_scans(database: str | Path, limit: int = 10) -> tuple[ScanSummary, ...]:
    """Completed scans, newest first - a queued or failed scan cannot be a side."""
    if limit < 1:
        raise CompareError("limit must be at least 1")
    conn = open_database(database, readonly=True)
    try:
        rows = conn.execute(
            "SELECT id, started_at, targets_json FROM scans"
            " WHERE status = 'completed'"
            " ORDER BY started_at DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    return tuple(ScanSummary(str(row[0]), str(row[1]), str(row[2])) for row in rows)


def resolve_scan(database: str | Path, token: str) -> ScanSummary:
    """Accept a full id or any unique prefix, because nobody retypes a UUID."""
    conn = open_database(database, readonly=True)
    try:
        rows = conn.execute(
            "SELECT id, started_at, targets_json FROM scans WHERE id LIKE ?"
            " ORDER BY started_at DESC LIMIT 2",
            (f"{token}%",),
        ).fetchall()
    finally:
        conn.close()
    if not rows:
        raise CompareError(f"no scan matches {token!r}")
    if len(rows) > 1 and str(rows[0][0]) != token:
        raise CompareError(f"{token!r} matches more than one scan; use more characters")
    return ScanSummary(str(rows[0][0]), str(rows[0][1]), str(rows[0][2]))


def _side(conn: sqlite3.Connection, scan_id: str) -> dict[str, tuple[str, dict[str, PortLine]]]:
    """address -> (hostname, port lines) for one scan."""
    rows = conn.execute(
        """
        SELECT ho.id AS host_id,
               COALESCE(ho.hostname, '') AS hostname,
               COALESCE((SELECT a.display_value FROM observation_addresses oa
                         JOIN addresses a ON a.id = oa.address_id
                         WHERE oa.host_observation_id = ho.id
                         ORDER BY CASE WHEN a.display_value LIKE '%:%' THEN 1 ELSE 0 END,
                                  a.display_value LIMIT 1), '') AS address
        FROM host_observations ho
        WHERE ho.scan_id = ?
        ORDER BY ho.id
        """,
        (scan_id,),
    ).fetchall()
    side: dict[str, tuple[str, dict[str, PortLine]]] = {}
    for host_id, hostname, address in rows:
        if not address:
            continue  # a host with no address cannot be matched across scans
        ports = {
            line.key: line
            for line in _ports(conn, str(host_id))
        }
        previous = side.get(str(address))
        if previous is None:
            side[str(address)] = (str(hostname), ports)
            continue
        merged = dict(previous[1])
        for key, line in ports.items():
            merged.setdefault(key, line)
        side[str(address)] = (previous[0] or str(hostname), merged)
    return side


def _ports(conn: sqlite3.Connection, host_id: str) -> list[PortLine]:
    rows = conn.execute(
        "SELECT protocol, port, state, COALESCE(service, '') FROM port_observations"
        " WHERE host_observation_id = ? ORDER BY port, protocol",
        (host_id,),
    ).fetchall()
    return [
        PortLine(str(protocol), int(port), str(state), str(service))
        for protocol, port, state, service in rows
    ]


def diff_scans(database: str | Path, left_id: str, right_id: str) -> ScanDiff:
    """Compare two scans of the same engagement, left = before, right = after."""
    if left_id == right_id:
        raise CompareError("a scan cannot be compared with itself")
    conn = open_database(database, readonly=True)
    try:
        left = _summary(conn, left_id)
        right = _summary(conn, right_id)
        before = _side(conn, left_id)
        after = _side(conn, right_id)
    finally:
        conn.close()

    hosts: list[HostChange] = []
    for address in sorted(set(before) | set(after)):
        old = before.get(address)
        new = after.get(address)
        if old is None:
            hosts.append(
                HostChange(address, new[0] if new else "", ADDED,
                           ports_added=tuple(new[1][key] for key in sorted(new[1])) if new else ())
            )
            continue
        if new is None:
            hosts.append(
                HostChange(address, old[0], REMOVED,
                           ports_removed=tuple(old[1][key] for key in sorted(old[1])))
            )
            continue
        added = tuple(new[1][key] for key in sorted(new[1]) if key not in old[1])
        removed = tuple(old[1][key] for key in sorted(old[1]) if key not in new[1])
        changed = tuple(
            (old[1][key], new[1][key])
            for key in sorted(old[1])
            if key in new[1] and (old[1][key].state, old[1][key].service)
            != (new[1][key].state, new[1][key].service)
        )
        status = CHANGED if (added or removed or changed) else UNCHANGED
        hosts.append(
            HostChange(address, new[0] or old[0], status, added, removed, changed)
        )
    return ScanDiff(
        left=left,
        right=right,
        hosts=tuple(hosts),
        hosts_per_side={"left": len(before), "right": len(after)},
    )


def _summary(conn: sqlite3.Connection, scan_id: str) -> ScanSummary:
    row = conn.execute(
        "SELECT id, started_at, targets_json FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    if row is None:
        raise CompareError(f"scan {scan_id} does not exist in this engagement")
    return ScanSummary(str(row[0]), str(row[1]), str(row[2]))


def render_text(diff: ScanDiff) -> str:
    """Plain text, safe for a pipe: no colour, no unicode, no box drawing."""
    lines = [
        f"before: {diff.left.id}  ({diff.left.started_at})",
        f"after:  {diff.right.id}  ({diff.right.started_at})",
        f"hosts:  {diff.hosts_per_side.get('left', 0)} -> {diff.hosts_per_side.get('right', 0)}"
        f"   {diff.summary_line}",
        "",
    ]
    for status, heading in ((ADDED, "appeared"), (REMOVED, "gone"), (CHANGED, "changed")):
        rows = diff.by_status(status)
        if not rows:
            continue
        lines.append(f"{heading}:")
        for host in rows:
            label = host.address + (f" ({host.hostname})" if host.hostname else "")
            lines.append(f"  {label}")
            for line in host.ports_added:
                lines.append(f"    + {line}")
            for line in host.ports_removed:
                lines.append(f"    - {line}")
            for old, new in host.ports_changed:
                lines.append(f"    ~ {old}  ->  {new}")
        lines.append("")
    if not any(host.status != UNCHANGED for host in diff.hosts):
        lines.append("no differences between these two scans")
    return "\n".join(lines).rstrip() + "\n"