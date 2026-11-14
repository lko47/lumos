"""Manual nodes and links: what the operator knows and the scanner cannot see.

A manual node is a claim, not an observation, so it is stored as
``kind = 'manual'`` and the inference pass never prunes it - it only rebuilds
its own derived zones and links. A manual link is ``edge_type = 'manual'`` and
therefore carries full confidence in the map and in every export.

Nothing here guesses: a link needs two nodes that exist, a node needs a label,
and both record who made the claim.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path

from ..core.database import open_database, utc_now
from ..core.ids import ensure_engagement_uid
from ..core.text import sanitize_text

MAX_LABEL = 120
MAX_NOTE = 400
NODE_TYPES = ("device", "segment", "external")


class ManualError(ValueError):
    """A manual claim that cannot be stored, with the reason in the sentence."""


@dataclass(frozen=True)
class ManualNode:
    node_id: str
    manual_id: str
    label: str
    node_type: str
    description: str
    author: str


def _clean(value: object, *, limit: int, what: str) -> str:
    text = sanitize_text(value, max_chars=limit).strip()
    if not text:
        raise ManualError(f"a manual {what} needs a value")
    return text


def _engagement(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()
    if row is None:
        raise ManualError("database has no engagement")
    return str(row[0])


def add_node(
    database: str | Path,
    *,
    label: str,
    author: str,
    node_type: str = "device",
    description: str = "",
) -> ManualNode:
    """Add a node the scanner did not find; it survives every rebuild."""
    if node_type not in NODE_TYPES:
        raise ManualError(f"unknown manual node type {node_type!r}")
    clean_label = _clean(label, limit=MAX_LABEL, what="node")
    clean_author = _clean(author, limit=64, what="author")
    clean_description = sanitize_text(description, max_chars=MAX_NOTE)
    manual_id = str(uuid.uuid4())
    node_id = str(uuid.uuid4())
    now = utc_now()
    conn = open_database(database)
    try:
        with conn:
            engagement_id = _engagement(conn)
            ensure_engagement_uid(conn)
            exists = conn.execute(
                "SELECT id FROM manual_nodes WHERE engagement_id = ? AND label = ?",
                (engagement_id, clean_label),
            ).fetchone()
            if exists is not None:
                raise ManualError(f"a manual node called {clean_label!r} already exists")
            conn.execute(
                "INSERT INTO manual_nodes (id, engagement_id, node_type, label, description,"
                " author, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (manual_id, engagement_id, node_type, clean_label, clean_description,
                 clean_author, now),
            )
            conn.execute(
                "INSERT INTO topology_nodes (id, engagement_id, kind, entity_id, label,"
                " created_at) VALUES (?, ?, 'manual', ?, ?, ?)",
                (node_id, engagement_id, manual_id, clean_label, now),
            )
    finally:
        conn.close()
    return ManualNode(node_id, manual_id, clean_label, node_type, clean_description, clean_author)


def list_nodes(database: str | Path) -> tuple[ManualNode, ...]:
    conn = open_database(database, readonly=True)
    try:
        rows = conn.execute(
            "SELECT t.id, m.id, m.label, m.node_type, m.description, m.author"
            " FROM manual_nodes m JOIN topology_nodes t ON t.entity_id = m.id"
            " WHERE t.kind = 'manual' ORDER BY m.created_at, m.label"
        ).fetchall()
    finally:
        conn.close()
    return tuple(
        ManualNode(str(node), str(manual), str(label), str(kind), str(desc), str(author))
        for node, manual, label, kind, desc, author in rows
    )


def _node(conn: sqlite3.Connection, node_id: str) -> tuple[str, str]:
    row = conn.execute(
        "SELECT id, kind FROM topology_nodes WHERE id = ?", (node_id,)
    ).fetchone()
    if row is None:
        raise ManualError(f"no topology node {node_id}")
    return str(row[0]), str(row[1])


def add_link(
    database: str | Path,
    *,
    from_node: str,
    to_node: str,
    author: str,
    note: str = "",
) -> str:
    """Connect two existing nodes; the link is manual and never animated."""
    if from_node == to_node:
        raise ManualError("a link needs two different nodes")
    clean_author = _clean(author, limit=64, what="author")
    clean_note = sanitize_text(note, max_chars=MAX_NOTE)
    now = utc_now()
    edge_id = str(uuid.uuid4())
    conn = open_database(database)
    try:
        with conn:
            engagement_id = _engagement(conn)
            _node(conn, from_node)
            _node(conn, to_node)
            existing = conn.execute(
                "SELECT id FROM topology_edges WHERE engagement_id = ? AND"
                " ((from_node_id = ? AND to_node_id = ?) OR (from_node_id = ? AND to_node_id = ?))",
                (engagement_id, from_node, to_node, to_node, from_node),
            ).fetchone()
            if existing is not None:
                raise ManualError("those nodes are already connected")
            conn.execute(
                "INSERT INTO topology_edges (id, engagement_id, from_node_id, to_node_id,"
                " edge_type, source_kind, source_id, confidence, first_observed_at, author)"
                " VALUES (?, ?, ?, ?, 'manual', 'manual', ?, 1.0, ?, ?)",
                (edge_id, engagement_id, from_node, to_node, edge_id, now, clean_author),
            )
    finally:
        conn.close()
    return edge_id


def links(database: str | Path) -> tuple[tuple[str, str, str], ...]:
    """(edge id, from label, to label) for every manual link."""
    conn = open_database(database, readonly=True)
    try:
        rows = conn.execute(
            "SELECT e.id, a.label, b.label FROM topology_edges e"
            " JOIN topology_nodes a ON a.id = e.from_node_id"
            " JOIN topology_nodes b ON b.id = e.to_node_id"
            " WHERE e.edge_type = 'manual' ORDER BY e.first_observed_at"
        ).fetchall()
    finally:
        conn.close()
    return tuple((str(edge), str(source), str(target)) for edge, source, target in rows)


def remove_node(database: str | Path, node_id: str) -> None:
    """Delete a manual node and its links; a scanned node is refused."""
    conn = open_database(database)
    try:
        with conn:
            _node(conn, node_id)
            kind = conn.execute(
                "SELECT kind FROM topology_nodes WHERE id = ?", (node_id,)
            ).fetchone()[0]
            if str(kind) != "manual":
                raise ManualError("only manual nodes can be removed here")
            entity = conn.execute(
                "SELECT entity_id FROM topology_nodes WHERE id = ?", (node_id,)
            ).fetchone()[0]
            conn.execute(
                "DELETE FROM topology_edges WHERE from_node_id = ? OR to_node_id = ?",
                (node_id, node_id),
            )
            conn.execute("DELETE FROM topology_nodes WHERE id = ?", (node_id,))
            conn.execute("DELETE FROM manual_nodes WHERE id = ?", (entity,))
    finally:
        conn.close()


def remove_link(database: str | Path, edge_id: str) -> None:
    conn = open_database(database)
    try:
        with conn:
            row = conn.execute(
                "SELECT edge_type FROM topology_edges WHERE id = ?", (edge_id,)
            ).fetchone()
            if row is None:
                raise ManualError(f"no link {edge_id}")
            if str(row[0]) != "manual":
                raise ManualError("only manual links can be removed")
            conn.execute("DELETE FROM topology_edges WHERE id = ?", (edge_id,))
    finally:
        conn.close()