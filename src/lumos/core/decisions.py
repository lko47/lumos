"""Record a human decision about an inferred link, and explain links in words."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from . import ids
from .database import open_database, utc_now
from .evidence import classify
from .inference import rebuild_inferred
from .text import sanitize_text

DECISIONS = ("promoted", "rejected")


class DecisionError(ValueError):
    """The decision cannot be applied to that link."""


def describe_edge(
    rule: str,
    evidence: dict,
    confidence: float,
    *,
    source_label: str = "",
    destination_label: str = "",
) -> str:
    """A plain-English sentence naming the rule and the facts it used."""
    rule = rule or "unknown"
    address = str(evidence.get("address") or "")
    cidr = str(evidence.get("cidr") or "")
    interface = str(evidence.get("interface") or "")
    gateway = str(evidence.get("gateway") or "")
    reason = str(evidence.get("reason") or "")
    assumed = bool(evidence.get("assumed_prefix"))

    if rule == "local_interface":
        text = (
            f"The scanner's own interface {interface or 'unknown'} holds {address or 'an address'}"
            f" in {cidr or 'a connected network'}."
        )
        prefix = "Local"
    elif rule == "on_link_arp":
        answered = "answered ARP" if reason.lower() != "ndr" else "answered neighbour discovery"
        text = f"{address or 'The host'} is inside {cidr or 'the connected network'} on {interface or 'an interface'} and {answered}."
        prefix = "Inferred"
    elif rule == "on_link_address":
        text = (
            f"{address or 'The host'} is inside {cidr or 'the connected network'} on "
            f"{interface or 'an interface'}; no ARP or MAC evidence was recorded."
        )
        prefix = "Inferred"
    elif rule == "gateway_on_link":
        text = f"The route's gateway {gateway or 'unknown'} sits inside {cidr or 'the connected network'}."
        prefix = "Inferred"
    elif rule == "routed_via_gateway":
        text = f"The route to {cidr or source_label or 'the destination'} goes through gateway {gateway or 'unknown'}."
        if assumed:
            text += " The prefix was assumed (/24 or /64), not supplied by a route or network."
        prefix = "Inferred"
    elif rule == "unknown_path":
        text = "No interface or route data was recorded for this scanner, so the path is unknown."
        prefix = "Inferred"
    else:
        text = f"{source_label or 'This node'} to {destination_label or 'that node'}."
        prefix = "Inferred"
    return f"{prefix} by {rule}: {text} Confidence {confidence:.2f}."


def record_decision(
    database: str | Path,
    edge_id: str,
    decision: str,
    *,
    author: str = "",
    now: str | None = None,
) -> str:
    """Apply a promote/reject decision, then let the engine re-derive.

    Promoted links become manual edges owned by the author; rejected links are
    removed and never regenerated. Both are append-only in ``edge_decisions`` so
    a rebuild or a merge keeps the operator's choice.
    """
    if decision not in DECISIONS:
        raise DecisionError(f"Unknown decision {decision!r}")
    stamp = now or utc_now()
    conn = open_database(database, readonly=False)
    try:
        engagement = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()
        if engagement is None:
            raise DecisionError("Database has no engagement")
        engagement_id = str(engagement[0])
        uid = ids.ensure_engagement_uid(conn)
        edge = conn.execute(
            "SELECT id, from_node_id, to_node_id, edge_type, confidence, source_kind, derived "
            "FROM topology_edges WHERE id = ? AND engagement_id = ?",
            (edge_id, engagement_id),
        ).fetchone()
        if edge is None:
            raise DecisionError("That link no longer exists; reload the map")
        if edge["edge_type"] != "inferred" or not int(edge["derived"] or 0):
            raise DecisionError("Only inferred links can be promoted or rejected")
        with conn:
            conn.execute(
                "INSERT INTO edge_decisions(id, engagement_id, edge_id, decision, author, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
                (
                    ids.edge_decision_id(uid, edge_id, decision, stamp),
                    engagement_id,
                    edge_id,
                    decision,
                    sanitize_text(author, max_chars=256),
                    stamp,
                ),
            )
            if decision == "promoted":
                conn.execute(
                    "INSERT INTO topology_edges(id, engagement_id, from_node_id, to_node_id, edge_type, "
                    "source_kind, source_id, confidence, first_observed_at, last_confirmed_at, author, "
                    "derived, evidence_json) VALUES (?, ?, ?, ?, 'manual', 'promotion', ?, 1.0, ?, ?, ?, 0, ?) "
                    "ON CONFLICT DO NOTHING",
                    (
                        ids.edge_id(uid, str(edge["from_node_id"]), str(edge["to_node_id"]), "manual", f"promoted:{edge_id}"),
                        engagement_id,
                        str(edge["from_node_id"]),
                        str(edge["to_node_id"]),
                        edge_id,
                        stamp,
                        stamp,
                        sanitize_text(author, max_chars=256),
                        json.dumps({"promoted_from": edge_id}, sort_keys=True),
                    ),
                )
            conn.execute(
                "DELETE FROM topology_edges WHERE id = ? AND derived = 1", (edge_id,)
            )
    finally:
        conn.close()
    # Re-derive so memberships and other links stay consistent; the decision
    # itself makes sure this edge is not recreated.
    rebuild_inferred(database)
    return decision


def edge_kind_label(edge_type: str, confidence: float) -> str:
    """Small helper so callers use the same vocabulary as the map."""
    return classify(edge_type, confidence)
