"""Persistence helpers for engagement scope and named networks."""

from __future__ import annotations

from pathlib import Path

from . import ids
from .database import open_database, utc_now
from .scope import ScopeRule, parse_target, parse_scope_rule
from .text import sanitize_text


def add_scope_rule(
    database_path: str | Path,
    network_name: str,
    target: str,
    *,
    included: bool,
    author: str = "",
) -> tuple[str, bool]:
    """Add an idempotent allow/exclude rule and ensure its named network exists."""
    network_name = sanitize_text(network_name, max_chars=512).strip()
    author = sanitize_text(author, max_chars=256).strip()
    if not network_name:
        raise ValueError("Network name must not be empty")
    spec = parse_target(target)
    rule = parse_scope_rule(target, included=included)
    conn = open_database(database_path)
    try:
        engagement = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()
        if engagement is None:
            raise ValueError("Database has no engagement")
        engagement_id = engagement[0]
        engagement_uid = ids.ensure_engagement_uid(conn)
        network = conn.execute(
            "SELECT id, family, cidr FROM networks WHERE engagement_id = ? AND name = ?",
            (engagement_id, network_name),
        ).fetchone()
        now = utc_now()
        if network is None:
            network_id = ids.network_id(engagement_uid, network_name)
            cidr = spec.canonical if spec.kind == "cidr" else None
            family = spec.family if spec.kind != "hostname" else None
            conn.execute(
                "INSERT INTO networks(id, engagement_id, name, cidr, family, notes, created_at) "
                "VALUES (?, ?, ?, ?, ?, '', ?) ON CONFLICT DO NOTHING",
                (network_id, engagement_id, network_name, cidr, family, now),
            )
            stored = conn.execute(
                "SELECT id FROM networks WHERE engagement_id = ? AND name = ?",
                (engagement_id, network_name),
            ).fetchone()
            if stored is not None:
                network_id = str(stored[0])
        else:
            network_id = network[0]
            old_family = network[1]
            new_family = spec.family
            if old_family is not None and new_family is not None and old_family != new_family:
                conn.execute(
                    "UPDATE networks SET family = NULL, cidr = NULL WHERE id = ?",
                    (network_id,),
                )
            elif network[2] is None and spec.kind == "cidr":
                conn.execute("UPDATE networks SET cidr = ?, family = ? WHERE id = ?", (spec.canonical, spec.family, network_id))
        existing = conn.execute(
            "SELECT id FROM scope_rules WHERE engagement_id = ? AND rule_kind = ? "
            "AND rule_value = ? AND included = ?",
            (engagement_id, rule.rule_kind, rule.rule_value, int(included)),
        ).fetchone()
        if existing is not None:
            conn.commit()
            return network_id, False
        conn.execute(
            "INSERT INTO scope_rules(id, engagement_id, rule_kind, rule_value, included, author, created_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT DO NOTHING",
            (
                ids.scope_rule_id(engagement_uid, rule.rule_kind, rule.rule_value, included),
                engagement_id,
                rule.rule_kind,
                rule.rule_value,
                int(included),
                author,
                now,
            ),
        )
        conn.commit()
        return network_id, True
    finally:
        conn.close()


def ensure_network(database_path: str | Path, network_name: str = "default") -> str:
    """Create an empty named network if needed and return its id.

    A network row is only a grouping label; creating one grants no scope.
    """
    name = (network_name or "default").strip() or "default"
    conn = open_database(database_path, readonly=False)
    try:
        engagement = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()
        if engagement is None:
            raise ValueError("Database has no engagement")
        engagement_id = engagement[0]
        engagement_uid = ids.ensure_engagement_uid(conn)
        with conn:
            network_id = ids.network_id(engagement_uid, name)
            conn.execute(
                "INSERT INTO networks(id, engagement_id, name, cidr, family, notes, created_at) "
                "VALUES (?, ?, ?, NULL, NULL, '', ?) ON CONFLICT DO NOTHING",
                (network_id, engagement_id, name, utc_now()),
            )
        row = conn.execute(
            "SELECT id FROM networks WHERE engagement_id = ? AND name = ?", (engagement_id, name)
        ).fetchone()
        if row is None:
            raise ValueError(f"Could not create network {name!r}")
        return str(row[0])
    finally:
        conn.close()


def get_network(database_path: str | Path, name: str) -> tuple[str, str]:
    """Return engagement and network UUIDs for a named network."""
    conn = open_database(database_path, readonly=True)
    try:
        engagement = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()
        if engagement is None:
            raise ValueError("Database has no engagement")
        row = conn.execute(
            "SELECT id FROM networks WHERE engagement_id = ? AND name = ?",
            (engagement[0], sanitize_text(name, max_chars=512).strip()),
        ).fetchone()
        if row is None:
            raise ValueError(f"Unknown network {name!r}; add it to scope first")
        return engagement[0], row[0]
    finally:
        conn.close()


def read_scope_rules(database_path: str | Path, engagement_id: str) -> list[ScopeRule]:
    conn = open_database(database_path, readonly=True)
    try:
        rows = conn.execute(
            "SELECT rule_kind, rule_value, included FROM scope_rules WHERE engagement_id = ?",
            (engagement_id,),
        )
        return [ScopeRule(bool(row[2]), row[0], row[1]) for row in rows]
    finally:
        conn.close()
