"""Tags: short labels attached to nodes, edges or the engagement.

A tag is a name plus a link. Names are normalised case-insensitively so that
"DMZ" and "dmz" are one tag, but the first spelling someone used is preserved
for display: an operator's capitalisation is information, not noise.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path

from ..core.database import open_database, utc_now
from ..core.text import sanitize_text

MAX_TAG_CHARS = 40
MAX_TAGS_PER_OBJECT = 24
OBJECT_KINDS = ("topology_node", "topology_edge", "engagement")


class TagError(ValueError):
    """A tag that cannot be applied or read, with the reason in the sentence."""


@dataclass(frozen=True)
class Tag:
    id: str
    name: str
    count: int = 0


def _normalise(name: str) -> str:
    return " ".join(sanitize_text(name).split()).casefold()


def _clean(name: str) -> str:
    text = " ".join(sanitize_text(name).split())
    if not text:
        raise TagError("a tag needs a name")
    if len(text) > MAX_TAG_CHARS:
        raise TagError(f"a tag is limited to {MAX_TAG_CHARS} characters")
    return text


def _engagement_id(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()
    if row is None:
        raise TagError("engagement database has no engagement row")
    return str(row[0])


def add_tag(
    database: str | Path,
    *,
    name: str,
    object_kind: str,
    object_id: str,
    author: str,
) -> Tag:
    """Attach a tag, creating it on first use. Applying twice is a no-op."""
    if object_kind not in OBJECT_KINDS:
        raise TagError(f"unknown tag target: {object_kind}")
    if object_kind != "engagement" and not object_id:
        raise TagError("a tag on a node or edge needs an id")
    clean = _clean(name)
    normalised = _normalise(clean)
    stamp = utc_now()
    conn = open_database(database)
    try:
        engagement = _engagement_id(conn)
        existing = conn.execute(
            "SELECT id, name FROM tags WHERE engagement_id = ? AND normalized_name = ?",
            (engagement, normalised),
        ).fetchone()
        with conn:
            if existing is None:
                if _links_for_object(conn, object_kind, object_id) >= MAX_TAGS_PER_OBJECT:
                    raise TagError(f"an object carries at most {MAX_TAGS_PER_OBJECT} tags")
                tag_id = str(uuid.uuid4())
                conn.execute(
                    "INSERT INTO tags (id, engagement_id, name, normalized_name, created_at)"
                    " VALUES (?, ?, ?, ?, ?)",
                    (tag_id, engagement, clean, normalised, stamp),
                )
            else:
                tag_id = str(existing[0])
            conn.execute(
                "INSERT OR IGNORE INTO tag_links"
                " (tag_id, object_kind, object_id, author, created_at)"
                " VALUES (?, ?, ?, ?, ?)",
                (tag_id, object_kind, object_id, sanitize_text(author)[:80] or "operator", stamp),
            )
    finally:
        conn.close()
    return Tag(tag_id, clean)


def _links_for_object(conn: sqlite3.Connection, object_kind: str, object_id: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM tag_links WHERE object_kind = ? AND object_id = ?",
        (object_kind, object_id),
    ).fetchone()
    return int(row[0] or 0)


def tags_for(
    database: str | Path, object_kind: str, object_id: str
) -> tuple[Tag, ...]:
    """Tags on one object, alphabetical."""
    conn = open_database(database, readonly=True)
    try:
        rows = conn.execute(
            "SELECT t.id, t.name FROM tags t"
            " JOIN tag_links l ON l.tag_id = t.id"
            " WHERE l.object_kind = ? AND l.object_id = ?"
            " ORDER BY t.normalized_name",
            (object_kind, object_id),
        ).fetchall()
    finally:
        conn.close()
    return tuple(Tag(str(row[0]), str(row[1])) for row in rows)


def all_tags(database: str | Path, limit: int = 50) -> tuple[Tag, ...]:
    """Every tag with how many objects carry it, busiest first."""
    if limit < 1:
        raise TagError("limit must be at least 1")
    conn = open_database(database, readonly=True)
    try:
        rows = conn.execute(
            "SELECT t.id, t.name, COUNT(l.object_id) AS uses FROM tags t"
            " LEFT JOIN tag_links l ON l.tag_id = t.id"
            " GROUP BY t.id ORDER BY uses DESC, t.normalized_name LIMIT ?",
            (limit,),
        ).fetchall()
    finally:
        conn.close()
    return tuple(Tag(str(row[0]), str(row[1]), int(row[2] or 0)) for row in rows)


def remove_tag(
    database: str | Path, *, name: str, object_kind: str, object_id: str
) -> bool:
    """Detach one tag from one object; True when something was removed."""
    normalised = _normalise(name)
    conn = open_database(database)
    try:
        with conn:
            cursor = conn.execute(
                "DELETE FROM tag_links WHERE object_kind = ? AND object_id = ?"
                " AND tag_id IN (SELECT id FROM tags WHERE normalized_name = ?)",
                (object_kind, object_id, normalised),
            )
            removed = cursor.rowcount > 0
            conn.execute(
                "DELETE FROM tags WHERE normalized_name = ?"
                " AND NOT EXISTS (SELECT 1 FROM tag_links WHERE tag_id = tags.id)",
                (normalised,),
            )
    finally:
        conn.close()
    return removed