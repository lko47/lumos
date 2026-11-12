"""Shared topology-node persistence helpers.

Nodes are keyed on their natural identity ``(engagement_id, kind, entity_id)``
and carry a deterministic id, so recording the same router twice reuses the
row instead of duplicating it. The unique-key lookup also keeps nodes created
by older builds (random ids) reusable.
"""

from __future__ import annotations

import sqlite3


class TopologyStoreError(RuntimeError):
    """A topology row could not be written."""


def label_improves(old: str, new: str) -> bool:
    """Prefer a resolved hostname over a bare address on a reused node."""
    if not new or new == old:
        return False
    if not old:
        return True
    return not any(char.isalpha() for char in old) and any(char.isalpha() for char in new)


def ensure_node(
    conn: sqlite3.Connection,
    engagement_id: str,
    node_id: str,
    kind: str,
    entity_id: str,
    label: str,
    created_at: str,
) -> str:
    """Create or reuse a topology node, returning the stored row id."""
    conn.execute(
        "INSERT INTO topology_nodes(id, engagement_id, kind, entity_id, label, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
        (node_id, engagement_id, kind, entity_id, str(label), created_at),
    )
    row = conn.execute(
        "SELECT id, label FROM topology_nodes WHERE engagement_id = ? AND kind = ? AND entity_id = ?",
        (engagement_id, kind, entity_id),
    ).fetchone()
    if row is None:
        raise TopologyStoreError(f"Could not record topology node {kind}:{entity_id}")
    if label_improves(str(row[1] or ""), str(label)):
        conn.execute("UPDATE topology_nodes SET label = ? WHERE id = ?", (str(label), row[0]))
    return str(row[0])
