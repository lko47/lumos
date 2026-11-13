"""Markdown, SVG, JSON, CSV and HTML reports using the standard library only."""

from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import math
import os
import re
from pathlib import Path
from typing import Iterator

from .database import open_database
from .evidence import SVG_STYLE, classify
from .text import sanitize_text


def _code(value: object) -> str:
    text = sanitize_text(value, max_chars=4096).replace("\n", " ")
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    delimiter = "`" * max(1, longest + 1)
    padding = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{delimiter}{padding}{text}{padding}{delimiter}"


def _fenced_block(value: object, language: str = "text") -> str:
    text = sanitize_text(value, max_chars=4096)
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{language}\n{text}\n{fence}\n"


def iter_markdown_report(database_path: str | Path) -> Iterator[str]:
    """Yield a Markdown engagement report without loading the inventory at once."""
    conn = open_database(database_path, readonly=True)
    try:
        engagement = conn.execute(
            "SELECT id, name, client, operator, created_at FROM engagement LIMIT 1"
        ).fetchone()
        if engagement is None:
            raise ValueError("Database has no engagement")
        engagement_id = engagement[0]
        counts = {
            "networks": conn.execute("SELECT COUNT(*) FROM networks WHERE engagement_id = ?", (engagement_id,)).fetchone()[0],
            "scans": conn.execute("SELECT COUNT(*) FROM scans WHERE engagement_id = ?", (engagement_id,)).fetchone()[0],
            "devices": conn.execute("SELECT COUNT(DISTINCT device_id) FROM host_observations WHERE scan_id IN (SELECT id FROM scans WHERE engagement_id = ?)", (engagement_id,)).fetchone()[0],
            "open_ports": conn.execute("SELECT COUNT(*) FROM port_observations p JOIN host_observations h ON h.id = p.host_observation_id JOIN scans s ON s.id = h.scan_id WHERE s.engagement_id = ? AND p.state = 'open'", (engagement_id,)).fetchone()[0],
            "pending_reviews": conn.execute(
                "SELECT COUNT(*) FROM review_items r WHERE r.engagement_id = ? AND "
                "(SELECT e.state FROM review_events e WHERE e.review_item_id = r.id ORDER BY e.created_at DESC LIMIT 1) "
                "IN ('unreviewed', 'flagged', 'out_of_scope')",
                (engagement_id,),
            ).fetchone()[0],
        }
        yield f"# Engagement: {_code(engagement[1])}\n\n"
        yield f"- Client: {_code(engagement[2])}\n- Operator: {_code(engagement[3])}\n- Database created: {_code(engagement[4])}\n"
        yield "\n## Summary\n\n"
        for label, key in (("Networks", "networks"), ("Scans and imports", "scans"), ("Observed devices", "devices"), ("Open port observations", "open_ports"), ("Items awaiting review", "pending_reviews")):
            yield f"- {label}: {counts[key]}\n"

        yield "\n## Scope\n\n"
        scope_rows = conn.execute(
            "SELECT rule_kind, rule_value, included, author, created_at FROM scope_rules "
            "WHERE engagement_id = ? ORDER BY included DESC, rule_kind, rule_value",
            (engagement_id,),
        )
        any_scope = False
        for row in scope_rows:
            any_scope = True
            mark = "IN" if row[2] else "EXCLUDE"
            yield f"- **{mark}** {_code(row[0])} {_code(row[1])} — author {_code(row[3])}, {_code(row[4])}\n"
        if not any_scope:
            yield "- No scope rules recorded.\n"

        yield "\n## Methodology and scan history\n\n"
        scans = conn.execute(
            "SELECT id, exact_args_json, targets_json, nmap_version, interface, operator, started_at, ended_at, exit_code, status, scope_override "
            "FROM scans WHERE engagement_id = ? ORDER BY started_at, id",
            (engagement_id,),
        )
        any_scan = False
        for row in scans:
            any_scan = True
            yield f"### Scan `{row[0]}`\n\n"
            yield f"- Status: {_code(row[9])}; exit: {_code(row[8])}; scope override: {'yes' if row[10] else 'no'}\n"
            yield f"- Nmap version: {_code(row[3])}; interface: {_code(row[4])}; operator: {_code(row[5])}\n"
            yield f"- Started: {_code(row[6])}; ended: {_code(row[7])}\n"
            yield f"- Arguments (credentials redacted): {_code(row[1])}\n- Targets: {_code(row[2])}\n\n"
        if not any_scan:
            yield "No scans or XML imports recorded.\n\n"

        yield "## Asset inventory\n\n"
        hosts = conn.execute(
            "SELECT h.id, h.device_id, h.hostname, h.reachability, h.os_name, h.os_accuracy, h.mac_vendor, h.observed_at, "
            "(SELECT GROUP_CONCAT(a.display_value, ', ') FROM observation_addresses oa JOIN addresses a ON a.id = oa.address_id WHERE oa.host_observation_id = h.id) AS addresses "
            "FROM host_observations h JOIN scans s ON s.id = h.scan_id WHERE s.engagement_id = ? "
            "ORDER BY h.observed_at, h.id",
            (engagement_id,),
        )
        any_host = False
        for row in hosts:
            any_host = True
            yield f"### {_code(row[2] or row[8] or row[1])}\n\n"
            yield f"- Device: {_code(row[1])}; observed: {_code(row[7])}; reachability: {_code(row[3])}\n"
            yield f"- Addresses: {_code(row[8])}; MAC vendor: {_code(row[6])}\n"
            yield f"- OS: {_code(row[4])} (accuracy {_code(row[5])})\n"
            ports = conn.execute(
                "SELECT protocol, port, state, service, product, version FROM port_observations WHERE host_observation_id = ? ORDER BY protocol, port",
                (row[0],),
            )
            port_list = list(ports)
            if port_list:
                yield "- Ports:\n"
                for port in port_list:
                    service = " ".join(part for part in (port[3], port[4], port[5]) if part)
                    yield f"  - {_code(port[0] + '/' + str(port[1]))}: {_code(port[2])}; {_code(service)}\n"
            else:
                yield "- Ports: none recorded\n"
            scripts = conn.execute(
                "SELECT script_id, output FROM script_observations WHERE host_observation_id = ? ORDER BY script_id, id",
                (row[0],),
            )
            for script in scripts:
                yield f"- Nmap script {_code(script[0])}:\n\n"
                yield _fenced_block(script[1]) + "\n"
            yield "\n"
        if not any_host:
            yield "No hosts observed.\n\n"

        yield "## Topology claims\n\n"
        edges = conn.execute(
            "SELECT e.edge_type, e.source_kind, e.confidence, a.label, b.label, e.first_observed_at, e.last_confirmed_at "
            "FROM topology_edges e JOIN topology_nodes a ON a.id = e.from_node_id JOIN topology_nodes b ON b.id = e.to_node_id "
            "WHERE e.engagement_id = ? ORDER BY e.first_observed_at, e.id",
            (engagement_id,),
        )
        any_edge = False
        for edge in edges:
            any_edge = True
            yield f"- {_code(edge[3])} → {_code(edge[4])}; type {_code(edge[0])}; source {_code(edge[1])}; confidence {edge[2]:.2f}; first seen {_code(edge[5])}; last confirmed {_code(edge[6])}\n"
        if not any_edge:
            yield "No topology edges recorded.\n"

        yield "\n## Inferred links (not measured)\n\n"
        inferred = conn.execute(
            "SELECT a.label, b.label, e.source_kind, e.confidence "
            "FROM topology_edges e JOIN topology_nodes a ON a.id = e.from_node_id "
            "JOIN topology_nodes b ON b.id = e.to_node_id "
            "WHERE e.engagement_id = ? AND e.edge_type = 'inferred' "
            "ORDER BY e.confidence DESC, a.label, b.label",
            (engagement_id,),
        ).fetchall()
        if inferred:
            yield (
                "Inferred links are derived from host addressing and the scanner's own interface "
                "and routing tables. They were not measured. The SVG report draws them dotted; "
                "solid lines are measurements.\n\n"
            )
            yield "| From | To | Rule | Confidence |\n| --- | --- | --- | --- |\n"
            for row in inferred:
                rule = str(row[2] or "").removeprefix("rule:")
                yield (
                    f"| {_code(row[0])} | {_code(row[1])} | {_code(rule)} | {row[3]:.2f} |\n"
                )
        else:
            yield "No inferred links: every recorded link was measured.\n"

        yield "\n## Review queue\n\n"
        reviews = conn.execute(
            "SELECT r.target_kind, r.target_id, r.reason_code, r.reason_detail, "
            "(SELECT e.state FROM review_events e WHERE e.review_item_id = r.id ORDER BY e.created_at DESC LIMIT 1) AS state, r.latest_event_at "
            "FROM review_items r WHERE r.engagement_id = ? ORDER BY r.latest_event_at DESC, r.id",
            (engagement_id,),
        )
        any_review = False
        for review in reviews:
            any_review = True
            yield f"- {_code(review[4])}: {_code(review[2])} on {_code(review[0] + '/' + review[1])} — {_code(review[3])} ({_code(review[5])})\n"
        if not any_review:
            yield "No review items.\n"

        yield "\n## Notes\n\n"
        notes = conn.execute(
            "SELECT target_kind, target_id, author, created_at, body_markdown FROM notes "
            "WHERE engagement_id = ? ORDER BY created_at, id",
            (engagement_id,),
        )
        any_note = False
        for note in notes:
            any_note = True
            yield f"### {_code(note[0] + '/' + (note[1] or 'engagement'))} — {_code(note[2])}, {_code(note[3])}\n\n"
            yield sanitize_text(note[4], max_chars=65536) + "\n\n"
        if not any_note:
            yield "No notes.\n\n"

        yield "## Audit log\n\n"
        audits = conn.execute(
            "SELECT event_type, argv_json, targets_json, operator, occurred_at, exit_code, scope_override, details_json "
            "FROM audit_events WHERE engagement_id = ? ORDER BY occurred_at, id",
            (engagement_id,),
        )
        any_audit = False
        for audit in audits:
            any_audit = True
            yield (
                f"- {_code(audit[4])} — {_code(audit[0])}; operator {_code(audit[3])}; "
                f"exit {_code(audit[5])}; override {'yes' if audit[6] else 'no'}; "
                f"arguments {_code(audit[1])}; targets {_code(audit[2])}; details {_code(audit[7])}\n"
            )
        if not any_audit:
            yield "No audit events recorded.\n"
    finally:
        conn.close()


def write_markdown_report(database_path: str | Path, output_path: str | Path) -> None:
    """Write a private-owner Markdown report, streaming database rows to disk."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink():
        raise ValueError("Refusing to write a report through a symbolic link")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(output, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            for chunk in iter_markdown_report(database_path):
                stream.write(chunk)
    except BaseException:
        try:
            os.close(fd)
        except OSError:
            pass
        raise
    try:
        output.chmod(0o600)
    except OSError:
        pass


def _svg_escape(value: object) -> str:
    text = str(value if value is not None else "")
    return (
        text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _ring_positions(nodes, edges, width: int, height: int) -> dict[str, tuple[float, float]]:
    """Deterministic radial placement: hop distance sets the ring, id sets the angle."""
    ids = [row[0] for row in nodes]
    adjacency: dict[str, set[str]] = {node_id: set() for node_id in ids}
    for edge in edges:
        if edge[0] in adjacency and edge[1] in adjacency and edge[0] != edge[1]:
            adjacency[edge[0]].add(edge[1])
            adjacency[edge[1]].add(edge[0])
    roots = [row[0] for row in nodes if row[1] == "root"] or ids[:1]
    distance: dict[str, int] = {root: 0 for root in roots}
    queue = list(roots)
    while queue:
        current = queue.pop(0)
        for neighbour in sorted(adjacency[current]):
            if neighbour not in distance:
                distance[neighbour] = distance[current] + 1
                queue.append(neighbour)
    max_distance = max(distance.values(), default=0) or 1
    centre_x, centre_y = width / 2, height / 2
    max_radius = min(width, height) / 2 - 70
    positions: dict[str, tuple[float, float]] = {}
    for row in nodes:
        node_id = row[0]
        if node_id in roots:
            positions[node_id] = (centre_x, centre_y)
            continue
        depth = distance.get(node_id, max_distance)
        digest = hashlib.sha1(node_id.encode("utf-8")).digest()
        angle = (int.from_bytes(digest[:4], "big") / 0xFFFFFFFF) * math.tau
        radius = (max_radius / max_distance) * depth
        positions[node_id] = (
            centre_x + math.cos(angle) * radius,
            centre_y + math.sin(angle) * radius * 0.72,
        )
    return positions


def iter_svg_report(
    database_path: str | Path, *, width: int = 1200, height: int = 800
) -> Iterator[str]:
    """Yield an SVG map where dotted lines mean inferred, never measured."""
    conn = open_database(database_path, readonly=True)
    try:
        engagement = conn.execute("SELECT id, name FROM engagement LIMIT 1").fetchone()
        if engagement is None:
            raise ValueError("Database has no engagement")
        engagement_id, name = engagement
        nodes = conn.execute(
            "SELECT tn.id, tn.kind, tn.label, tn.entity_id, "
            "(SELECT COUNT(*) FROM zone_memberships zm WHERE tn.kind = 'zone' AND zm.zone_id = tn.entity_id) "
            "FROM topology_nodes tn WHERE tn.engagement_id = ? ORDER BY tn.id",
            (engagement_id,),
        ).fetchall()
        edges = conn.execute(
            "SELECT e.from_node_id, e.to_node_id, e.edge_type, e.confidence, e.source_kind "
            "FROM topology_edges e WHERE e.engagement_id = ? ORDER BY e.id",
            (engagement_id,),
        ).fetchall()
    finally:
        conn.close()

    positions = _ring_positions(nodes, edges, width, height)
    yield f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
    yield f'viewBox="0 0 {width} {height}" role="img" aria-label="Lumos topology map">\n'
    yield "<title>Lumos topology map</title>\n"
    yield (
        "<desc>Solid lines are measured or local links. Dotted lines are inferred from "
        "addressing and the scanner routing table and were not measured.</desc>\n"
    )
    yield '<rect width="100%" height="100%" fill="#10131a"/>\n'
    yield (
        f'<text x="24" y="34" fill="#e6edf3" font-family="monospace" font-size="18">'
        f'{_svg_escape(name)}</text>\n'
    )
    yield (
        '<text x="24" y="56" fill="#8b949e" font-family="monospace" font-size="12">'
        'solid: measured or local  ·  dotted: inferred, not measured</text>\n'
    )

    for from_id, to_id, edge_type, confidence, source_kind in edges:
        start = positions.get(from_id)
        end = positions.get(to_id)
        if start is None or end is None:
            continue
        style = classify(edge_type, confidence)
        stroke_width, dash, colour = SVG_STYLE[style]
        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        yield (
            f'<line x1="{start[0]:.1f}" y1="{start[1]:.1f}" x2="{end[0]:.1f}" y2="{end[1]:.1f}" '
            f'stroke="{colour}" stroke-width="{stroke_width}"{dash_attr} '
            f'stroke-linecap="round"><title>{_svg_escape(style)} link '
            f'({_svg_escape(str(source_kind).removeprefix("rule:"))}, confidence {confidence:.2f})'
            f'</title></line>\n'
        )
        if style == "manual":
            mid_x, mid_y = (start[0] + end[0]) / 2, (start[1] + end[1]) / 2
            yield (
                f'<text x="{mid_x:.1f}" y="{mid_y:.1f}" fill="{colour}" font-family="monospace" '
                f'font-size="10" text-anchor="middle">M</text>\n'
            )

    # Labels sit outside the ring (away from the centre) and are nudged apart
    # vertically so a report never stacks two hostnames on one another.
    occupied: dict[str, list[tuple[float, float]]] = {"left": [], "right": []}
    centre_x = width / 2
    for node_id, kind, label, entity_id, members in nodes:
        point = positions.get(node_id)
        if point is None:
            continue
        x, y = point
        text = _svg_escape(label)
        if kind == "zone":
            size = 9
            yield (
                f'<polygon points="{x:.1f},{y - size:.1f} {x + size:.1f},{y:.1f} '
                f'{x:.1f},{y + size:.1f} {x - size:.1f},{y:.1f}" fill="none" '
                f'stroke="#c9a0ff" stroke-width="1.6"><title>hub {text}</title></polygon>\n'
            )
            caption = f"{text} · {members}" if members else text
        elif kind == "root":
            yield (
                f'<rect x="{x - 8:.1f}" y="{y - 8:.1f}" width="16" height="16" fill="none" '
                f'stroke="#f2f2f2" stroke-width="2"><title>scanner root</title></rect>\n'
            )
            caption = text
        elif kind == "unknown_hop" and str(entity_id or "").startswith("gateway:"):
            yield (
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="6" fill="none" stroke="#8b949e" '
                f'stroke-width="1.4"><title>placeholder gateway</title></circle>\n'
            )
            caption = text
        else:
            yield (
                f'<circle cx="{x:.1f}" cy="{y:.1f}" r="6" fill="#7fd1ff" fill-opacity="0.85">'
                f'<title>{text}</title></circle>\n'
            )
            caption = text

        side = "right" if x >= centre_x else "left"
        anchor_x = x + 12 if side == "right" else x - 12
        anchor = "start" if side == "right" else "end"
        label_y = y + 4
        while any(
            abs(label_y - other_y) < 13 and abs(anchor_x - other_x) < 150
            for other_x, other_y in occupied[side]
        ):
            label_y += 13
        occupied[side].append((anchor_x, label_y))
        yield (
            f'<text x="{anchor_x:.1f}" y="{label_y:.1f}" fill="#c9d1d9" font-family="monospace" '
            f'font-size="10" text-anchor="{anchor}">{_svg_escape(caption)}</text>\n'
        )

    yield (
        f'<text x="24" y="{height - 20}" fill="#8b949e" font-family="monospace" font-size="11">'
        'Inferred links come from addressing and the scanner\u2019s routing table; '
        'they are not measurements.</text>\n'
    )
    yield "</svg>\n"


def write_svg_report(
    database_path: str | Path,
    output_path: str | Path,
    *,
    width: int = 1200,
    height: int = 800,
) -> None:
    """Write an owner-only SVG map report, refusing to follow a symlink."""
    target = Path(output_path)
    if target.is_symlink():
        raise ValueError(f"Refusing to write through a symlink: {target}")
    payload = "".join(iter_svg_report(database_path, width=width, height=height))
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(payload, encoding="utf-8")
    target.chmod(0o600)


# --- machine-readable reports ------------------------------------------------

REPORT_FORMATS = ("markdown", "svg", "json", "csv", "html")


def _rows(database_path: str | Path, statement: str, params: tuple = ()) -> list[tuple]:
    conn = open_database(database_path, readonly=True)
    try:
        return conn.execute(statement, params).fetchall()
    finally:
        conn.close()


def _host_rows(database_path: str | Path) -> list[dict]:
    """One record per host of the newest observation, deterministic order."""
    rows = _rows(
        database_path,
        """
        SELECT a.display_value AS address,
               COALESCE(h.hostname, '') AS hostname,
               COALESCE(h.os_name, '') AS os_name,
               s.id AS scan_id, s.started_at AS scanned_at
        FROM host_observations h
        JOIN scans s ON s.id = h.scan_id
        LEFT JOIN observation_addresses oa ON oa.host_observation_id = h.id
        LEFT JOIN addresses a ON a.id = oa.address_id
        WHERE h.id = (
            SELECT h2.id FROM host_observations h2
            WHERE h2.device_id = h.device_id
            ORDER BY h2.observed_at DESC, h2.id DESC LIMIT 1
        )
        ORDER BY address, h.id
        """,
    )
    seen: dict[str, dict] = {}
    for address, hostname, os_name, scan_id, scanned_at in rows:
        key = str(address or "")
        if not key or key in seen:
            continue
        seen[key] = {
            "address": sanitize_text(key, max_chars=128),
            "hostname": sanitize_text(hostname, max_chars=256),
            "os": sanitize_text(os_name, max_chars=256),
            "scan_id": str(scan_id),
            "scanned_at": str(scanned_at),
            "ports": [],
        }
    if not seen:
        return []
    port_rows = _rows(
        database_path,
        """
        SELECT a.display_value AS address, p.protocol, p.port, p.state,
               COALESCE(p.service, ''), COALESCE(p.product, ''), COALESCE(p.version, '')
        FROM port_observations p
        JOIN host_observations h ON h.id = p.host_observation_id
        LEFT JOIN observation_addresses oa ON oa.host_observation_id = h.id
        LEFT JOIN addresses a ON a.id = oa.address_id
        WHERE h.id IN (
            SELECT h3.id FROM host_observations h3
            WHERE h3.observed_at = (
                SELECT MAX(h4.observed_at) FROM host_observations h4
                WHERE h4.device_id = h3.device_id
            )
        )
        ORDER BY address, p.port, p.protocol
        """,
    )
    for address, protocol, port, state, service, product, version in port_rows:
        host = seen.get(str(address or ""))
        if host is None:
            continue
        host["ports"].append({
            "protocol": sanitize_text(protocol, max_chars=8),
            "port": int(port),
            "state": sanitize_text(state, max_chars=16),
            "service": sanitize_text(service, max_chars=64),
            "product": sanitize_text(product, max_chars=128),
            "version": sanitize_text(version, max_chars=64),
        })
    return [seen[key] for key in sorted(seen)]


def build_json_report(database_path: str | Path) -> dict:
    """The engagement as data: hosts, ports, links, notes and tags.

    No wall-clock timestamp is included, so two exports of an unchanged
    engagement are byte-identical and can be diffed or hashed.
    """
    engagement = _rows(database_path, "SELECT id, name FROM engagement LIMIT 1")
    engagement_id, engagement_name = (
        (str(engagement[0][0]), str(engagement[0][1])) if engagement else ("", "")
    )
    edges = _rows(
        database_path,
        "SELECT id, from_node_id, to_node_id, edge_type, source_kind, confidence"
        " FROM topology_edges ORDER BY id",
    )
    notes = _rows(
        database_path,
        "SELECT target_kind, COALESCE(target_id, ''), body_markdown, author, updated_at"
        " FROM notes ORDER BY updated_at, id",
    )
    tags = _rows(
        database_path,
        "SELECT object_kind, object_id, t.name FROM tag_links l"
        " JOIN tags t ON t.id = l.tag_id ORDER BY t.name, l.object_id",
    )
    scans = _rows(
        database_path,
        "SELECT id, started_at, ended_at, status, targets_json FROM scans"
        " ORDER BY started_at, id",
    )
    return {
        "format": "lumos-engagement",
        "version": 1,
        "engagement": {"id": engagement_id, "name": engagement_name},
        "scans": [
            {
                "id": str(scan_id),
                "started_at": str(started_at or ""),
                "ended_at": str(ended_at or ""),
                "status": str(status),
                "targets": json.loads(targets or "[]"),
            }
            for scan_id, started_at, ended_at, status, targets in scans
        ],
        "hosts": _host_rows(database_path),
        "links": [
            {
                "id": str(edge_id),
                "from": str(source),
                "to": str(target),
                "type": str(edge_type),
                "source_kind": str(source_kind),
                "confidence": float(confidence or 0.0),
            }
            for edge_id, source, target, edge_type, source_kind, confidence in edges
        ],
        "notes": [
            {
                "target_kind": str(kind),
                "target_id": str(target_id),
                "body": str(body),
                "author": str(author),
                "updated_at": str(updated_at or ""),
            }
            for kind, target_id, body, author, updated_at in notes
        ],
        "tags": [
            {"object_kind": str(kind), "object_id": str(object_id), "name": str(name)}
            for kind, object_id, name in tags
        ],
    }


def _write_private(path: str | Path, text: str) -> None:
    """Owner-only, no symlinks - the same rule the Markdown report follows."""
    output = Path(path)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.is_symlink():
        raise ValueError("Refusing to write a report through a symbolic link")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(output, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(text)
    try:
        output.chmod(0o600)
    except OSError:
        pass


def write_json_report(database_path: str | Path, output_path: str | Path) -> None:
    payload = build_json_report(database_path)
    _write_private(output_path, json.dumps(payload, indent=2, sort_keys=False) + "\n")


def build_csv_report(database_path: str | Path) -> str:
    """One row per observable port; a host with no ports still gets a row."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow([
        "address", "hostname", "os", "protocol", "port", "state",
        "service", "product", "version", "scan_id", "scanned_at",
    ])
    for host in _host_rows(database_path):
        base = [host["address"], host["hostname"], host["os"]]
        tail = [host["scan_id"], host["scanned_at"]]
        if not host["ports"]:
            writer.writerow(base + ["", "", "", "", "", "", ""] + tail)
            continue
        for port in host["ports"]:
            writer.writerow(base + [
                port["protocol"], port["port"], port["state"], port["service"],
                port["product"], port["version"],
            ] + tail)
    return buffer.getvalue()


def write_csv_report(database_path: str | Path, output_path: str | Path) -> None:
    _write_private(output_path, build_csv_report(database_path))


def build_html_report(database_path: str | Path) -> str:
    """A single self-contained page: no script, no external assets, all escaped."""
    payload = build_json_report(database_path)
    name = html.escape(payload["engagement"]["name"])
    rows = []
    for host in payload["hosts"]:
        ports = ", ".join(
            f"{item['port']}/{html.escape(str(item['protocol']))} "
            f"{html.escape(str(item['state']))} {html.escape(str(item['service']))}".strip()
            for item in host["ports"]
        )
        rows.append(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>".format(
                html.escape(host["address"]),
                html.escape(host["hostname"]),
                html.escape(host["os"]),
                html.escape(ports or "-"),
            )
        )
    links = "".join(
        "<tr><td>{}</td><td>{}</td><td>{}</td><td>{:.2f}</td></tr>".format(
            html.escape(link["from"]), html.escape(link["to"]),
            html.escape(f"{link['type']} ({link['source_kind']})"), link["confidence"],
        )
        for link in payload["links"]
    )
    notes = "".join(
        "<li><strong>{}</strong>: {}</li>".format(
            html.escape(note["target_id"] or note["target_kind"]), html.escape(note["body"])
        )
        for note in payload["notes"]
    )
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Lumos report - {name}</title>
<style>
body {{ font: 14px/1.5 ui-monospace, monospace; margin: 2rem; color: #111; }}
table {{ border-collapse: collapse; margin: 1rem 0; }}
th, td {{ border: 1px solid #bbb; padding: 0.3rem 0.6rem; text-align: left; }}
th {{ background: #eee; }}
.dim {{ color: #666; }}
</style>
</head>
<body>
<h1>{name}</h1>
<p class="dim">{len(payload["hosts"])} host(s), {len(payload["links"])} link(s),
{len(payload["scans"])} scan(s). Inferred links are labelled, never presented as measured.</p>
<h2>Hosts</h2>
<table><thead><tr><th>address</th><th>hostname</th><th>OS</th><th>ports</th></tr></thead>
<tbody>{"".join(rows) or "<tr><td colspan=\"4\">no hosts</td></tr>"}</tbody></table>
<h2>Links</h2>
<table><thead><tr><th>from</th><th>to</th><th>evidence</th><th>confidence</th></tr></thead>
<tbody>{links or "<tr><td colspan=\"4\">no links</td></tr>"}</tbody></table>
<h2>Notes</h2>
<ul>{notes or "<li>none</li>"}</ul>
</body>
</html>
"""


def write_html_report(database_path: str | Path, output_path: str | Path) -> None:
    _write_private(output_path, build_html_report(database_path))
