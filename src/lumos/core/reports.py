"""Markdown report generation using the standard library only."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Iterator

from .database import open_database
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
