"""Duplicate device proposals: the scanner suspects, a human decides.

Two observations that share an address or a hostname may be the same physical
device, but Lumos never merges identity on its own - a wrong merge silently
rewrites history. The proposal is recorded at scan time; accepting it here is
the only path to a merge, and it is append-only in the audit trail: the
decision is an event, the pair of devices is not deleted from the record of
what was seen.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path

from ..core.database import open_database, utc_now
from ..core.inference import rebuild_inferred
from ..core.ids import ensure_engagement_uid
from ..core.text import sanitize_text

MAX_LISTED = 200
DECISIONS = ("accepted_link", "rejected")


class DuplicateError(ValueError):
    """A proposal that cannot be decided, with the reason in the sentence."""


@dataclass(frozen=True)
class Proposal:
    id: str
    left_id: str
    right_id: str
    left_label: str
    right_label: str
    evidence: dict
    created_at: str
    decision: str = ""

    @property
    def summary(self) -> str:
        left = self.left_label or self.left_id[:8]
        right = self.right_label or self.right_id[:8]
        return f"{left} == {right}"

    @property
    def short_id(self) -> str:
        return self.id[:8]


def _label(conn: sqlite3.Connection, device_id: str) -> str:
    row = conn.execute(
        "SELECT label FROM topology_nodes WHERE kind = 'device' AND entity_id = ?",
        (device_id,),
    ).fetchone()
    return str(row[0]) if row else ""


def _decision(conn: sqlite3.Connection, proposal_id: str) -> str:
    row = conn.execute(
        "SELECT decision FROM duplicate_proposal_events WHERE proposal_id = ?"
        " ORDER BY created_at DESC, id DESC LIMIT 1",
        (proposal_id,),
    ).fetchone()
    return str(row[0]) if row else ""


def list_proposals(database: str | Path, *, include_decided: bool = False) -> tuple[Proposal, ...]:
    """Open proposals by default; the newest decision is the current state."""
    conn = open_database(database, readonly=True)
    try:
        rows = conn.execute(
            "SELECT id, left_id, right_id, evidence_json, created_at FROM duplicate_proposals"
            " ORDER BY created_at DESC, id LIMIT ?",
            (MAX_LISTED,),
        ).fetchall()
        proposals = []
        for proposal_id, left, right, evidence, created_at in rows:
            decision = _decision(conn, str(proposal_id))
            if decision and not include_decided:
                continue
            proposals.append(
                Proposal(
                    id=str(proposal_id),
                    left_id=str(left),
                    right_id=str(right),
                    left_label=_label(conn, str(left)),
                    right_label=_label(conn, str(right)),
                    evidence=_safe_json(evidence),
                    created_at=str(created_at or ""),
                    decision=decision,
                )
            )
    finally:
        conn.close()
    return tuple(proposals)


def _safe_json(value: object) -> dict:
    try:
        loaded = json.loads(str(value or "{}"))
    except (TypeError, ValueError):
        return {}
    return loaded if isinstance(loaded, dict) else {}


def _move(conn: sqlite3.Connection, table: str, column: str, source: str, target: str) -> None:
    conn.execute(f"UPDATE {table} SET {column} = ? WHERE {column} = ?", (target, source))


def _merge_devices(conn: sqlite3.Connection, keep_id: str, drop_id: str) -> None:
    """Re-point every observation at the surviving device, then retire the node."""
    _move(conn, "host_observations", "device_id", drop_id, keep_id)
    _move(conn, "identity_claims", "device_id", drop_id, keep_id)
    keep_node = conn.execute(
        "SELECT id FROM topology_nodes WHERE kind = 'device' AND entity_id = ?", (keep_id,)
    ).fetchone()
    drop_node = conn.execute(
        "SELECT id FROM topology_nodes WHERE kind = 'device' AND entity_id = ?", (drop_id,)
    ).fetchone()
    if keep_node is None or drop_node is None:
        conn.execute("DELETE FROM devices WHERE id = ?", (drop_id,))
        return
    # Re-point one edge at a time: the two devices usually carry the same
    # derived links, and re-pointing both would collide with the unique key.
    # A collision means the surviving device already has that link, so the
    # duplicate is dropped rather than merged.
    edges = conn.execute(
        "SELECT id, from_node_id, to_node_id FROM topology_edges WHERE"
        " from_node_id = ? OR to_node_id = ?",
        (drop_node[0], drop_node[0]),
    ).fetchall()
    for edge_id, source, target in edges:
        new_source = keep_node[0] if source == drop_node[0] else source
        new_target = keep_node[0] if target == drop_node[0] else target
        if new_source == new_target:
            conn.execute("DELETE FROM topology_edges WHERE id = ?", (edge_id,))
            continue
        try:
            conn.execute(
                "UPDATE topology_edges SET from_node_id = ?, to_node_id = ? WHERE id = ?",
                (new_source, new_target, edge_id),
            )
        except sqlite3.IntegrityError:
            conn.execute("DELETE FROM topology_edges WHERE id = ?", (edge_id,))
    conn.execute("DELETE FROM topology_nodes WHERE id = ?", (drop_node[0],))
    conn.execute("DELETE FROM devices WHERE id = ?", (drop_id,))


def decide(
    database: str | Path,
    proposal_id: str,
    decision: str,
    *,
    author: str,
    detail: str = "",
) -> bool:
    """Accept (merge the two devices) or reject a proposal. Returns merged."""
    if decision not in DECISIONS:
        raise DuplicateError(f"decision must be one of {', '.join(DECISIONS)}")
    clean_author = sanitize_text(author, max_chars=64).strip()
    if not clean_author:
        raise DuplicateError("a decision needs an author")
    clean_detail = sanitize_text(detail, max_chars=400)
    merged = False
    conn = open_database(database)
    try:
        with conn:
            row = conn.execute(
                "SELECT left_id, right_id FROM duplicate_proposals WHERE id = ?",
                (proposal_id,),
            ).fetchone()
            if row is None:
                raise DuplicateError(f"no duplicate proposal {proposal_id}")
            if _decision(conn, proposal_id):
                raise DuplicateError("this proposal has already been decided")
            ensure_engagement_uid(conn)
            if decision == "accepted_link":
                _merge_devices(conn, str(row[0]), str(row[1]))
                merged = True
            conn.execute(
                "INSERT INTO duplicate_proposal_events (id, proposal_id, decision, author,"
                " created_at) VALUES (?, ?, ?, ?, ?)",
                (str(uuid.uuid4()), proposal_id, decision, clean_author, utc_now()),
            )
    finally:
        conn.close()
    if merged:
        rebuild_inferred(database)
    return merged