"""Deterministic, merge-safe identifiers.

Every row identity is a UUIDv5 over the fixed ``_LUMOS`` namespace, derived
from the row's *natural key*. Two databases that record the same observation
therefore derive the same id, so a merge can union rows instead of creating
duplicates, and re-importing the same scan is idempotent.

The engagement is the one identity a file cannot recompute from its own
contents alone, because two engagements may legitimately share a name. Its
stable identity is ``meta.engagement_uid``, derived once from the engagement
name and creation timestamp. Merge semantics:

* A source file is only mergeable when its ``engagement_uid`` equals the
  target's; a different uid means a different engagement and is rejected
  (``merge_log.outcome = 'rejected'``), never silently rehomed.
* Every ``engagement_id`` column in the source is rewritten to the local
  ``engagement.id``; ``engagement_uid`` stays unchanged. Child rows keep
  their ids because those ids are derived from the uid, not the row id.
* Because ids are derived from natural keys, merging the same source twice
  is idempotent: conflicting ids resolve with ``ON CONFLICT DO NOTHING`` or
  a last-confirmed update rather than duplication.
"""

from __future__ import annotations

import sqlite3
import uuid

_LUMOS = uuid.UUID("6f1f5a4c-8f4a-5c1e-9d43-6c1f0a7b2d10")
_SEP = "\x1f"

ENGAGEMENT = uuid.uuid5(_LUMOS, "engagement")
NETWORK = uuid.uuid5(_LUMOS, "network")
ADDRESS = uuid.uuid5(_LUMOS, "address")
DEVICE = uuid.uuid5(_LUMOS, "device")
VANTAGE = uuid.uuid5(_LUMOS, "vantage_point")
TOPOLOGY_NODE = uuid.uuid5(_LUMOS, "topology_node")
TOPOLOGY_EDGE = uuid.uuid5(_LUMOS, "topology_edge")
TAG = uuid.uuid5(_LUMOS, "tag")
SCOPE_RULE = uuid.uuid5(_LUMOS, "scope_rule")
REVIEW_ITEM = uuid.uuid5(_LUMOS, "review_item")
OBSERVATION = uuid.uuid5(_LUMOS, "observation")
PORT = uuid.uuid5(_LUMOS, "port_observation")
TRACE_PATH = uuid.uuid5(_LUMOS, "trace_path")
TRACE_HOP = uuid.uuid5(_LUMOS, "trace_hop")
IDENTITY_CLAIM = uuid.uuid5(_LUMOS, "identity_claim")
ZONE = uuid.uuid5(_LUMOS, "zone")
VANTAGE_ROUTE = uuid.uuid5(_LUMOS, "vantage_route")
EDGE_DECISION = uuid.uuid5(_LUMOS, "edge_decision")

ENGAGEMENT_UID_KEY = "engagement_uid"


def _make(namespace: uuid.UUID, *parts: object) -> str:
    return str(uuid.uuid5(namespace, _SEP.join(str(part) for part in parts)))


def engagement_uid(name: str, created_at: str) -> str:
    """Stable identity for an engagement: its name plus its creation instant."""
    return _make(ENGAGEMENT, "engagement", name, created_at)


def network_id(uid: str, name: str) -> str:
    return _make(NETWORK, uid, name)


def address_id(network: str, kind: str, normalized_value: str) -> str:
    return _make(ADDRESS, network, kind, normalized_value)


def device_id(uid: str, scan: str, ordinal: int) -> str:
    """A device is scoped to one scan observation position.

    Devices are deliberately *not* keyed on address or hostname: Lumos never
    auto-merges identity, so the same host seen twice stays two devices with
    a duplicate proposal until a human decides.
    """
    return _make(DEVICE, uid, scan, ordinal)


def vantage_id(uid: str, scanner_name: str) -> str:
    return _make(VANTAGE, uid, scanner_name)


def node_id(uid: str, kind: str, key: str) -> str:
    return _make(TOPOLOGY_NODE, uid, kind, key)


def edge_id(uid: str, from_node: str, to_node: str, edge_type: str, source_kind: str) -> str:
    return _make(TOPOLOGY_EDGE, uid, from_node, to_node, edge_type, source_kind)


def tag_id(uid: str, normalized_name: str) -> str:
    return _make(TAG, uid, normalized_name)


def scope_rule_id(uid: str, rule_kind: str, rule_value: str, included: bool) -> str:
    return _make(SCOPE_RULE, uid, rule_kind, rule_value, int(bool(included)))


def review_item_id(uid: str, target_kind: str, target_id: str, reason_code: str) -> str:
    return _make(REVIEW_ITEM, uid, target_kind, target_id, reason_code)


def observation_id(device: str) -> str:
    """One host observation per device row."""
    return _make(OBSERVATION, device)


def port_observation_id(observation: str, protocol: str, port: int) -> str:
    return _make(PORT, observation, protocol, port)


def trace_path_id(scan: str, destination_node: str, path_index: int) -> str:
    return _make(TRACE_PATH, scan, destination_node, path_index)


def trace_hop_id(path: str, hop_number: int) -> str:
    return _make(TRACE_HOP, path, hop_number)


def identity_claim_id(device: str, kind: str, normalized_value: str, source_observation_id: str) -> str:
    return _make(IDENTITY_CLAIM, device, kind, normalized_value, source_observation_id)


def zone_id(uid: str, network: str, cidr: str) -> str:
    """A segment hub is keyed on its network row *and* its CIDR.

    Two engagements that both contain 10.0.0.0/24 therefore keep separate
    hubs, while two scanners attached to the same network share one.
    """
    return _make(ZONE, uid, network, cidr)


def vantage_route_id(uid: str, vantage: str, dst_cidr: str, dev: str, metric: int, gateway: str) -> str:
    return _make(VANTAGE_ROUTE, uid, vantage, dst_cidr, dev, metric, gateway)


def edge_decision_id(uid: str, edge: str, decision: str, created_at: str) -> str:
    """Decisions are append-only, so the timestamp is part of the key."""
    return _make(EDGE_DECISION, uid, edge, decision, created_at)


def inferred_edge_id(uid: str, from_node: str, to_node: str, rule: str) -> str:
    """Id for a derived link; the rule is part of the key on purpose."""
    return edge_id(uid, from_node, to_node, "inferred", f"rule:{rule}")


def read_engagement_uid(conn: sqlite3.Connection) -> str:
    """Return the engagement's stable id, deriving (but not storing) it if absent.

    Read-only connections cannot write the derived value back; the next writer
    persists it via :func:`ensure_engagement_uid`.
    """
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (ENGAGEMENT_UID_KEY,)).fetchone()
    if row is not None and row[0]:
        return str(row[0])
    engagement = conn.execute("SELECT name, created_at FROM engagement LIMIT 1").fetchone()
    if engagement is None:
        raise ValueError("Database has no engagement")
    return engagement_uid(str(engagement[0]), str(engagement[1]))


def ensure_engagement_uid(conn: sqlite3.Connection) -> str:
    """Derive and persist ``meta.engagement_uid`` when missing."""
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (ENGAGEMENT_UID_KEY,)).fetchone()
    if row is not None and row[0]:
        return str(row[0])
    uid = read_engagement_uid(conn)
    from .database import utc_now

    conn.execute(
        "INSERT INTO meta(key, value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at",
        (ENGAGEMENT_UID_KEY, uid, utc_now()),
    )
    return uid


def merge_engagement_id(conn: sqlite3.Connection, source_uid: str) -> str:
    """Return the local engagement row id a merged file must be rebased onto.

    Raises when the source belongs to a different engagement; the caller is
    expected to record that rejection in ``merge_log``.
    """
    local_uid = read_engagement_uid(conn)
    if source_uid != local_uid:
        raise ValueError(
            "Cannot merge a different engagement: "
            f"source uid {source_uid} != local uid {local_uid}"
        )
    row = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()
    if row is None:
        raise ValueError("Database has no engagement")
    return str(row[0])
