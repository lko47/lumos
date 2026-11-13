"""Notes attached to a node, edge or the engagement itself.

A note is human judgement, so it is stored verbatim apart from terminal
sanitisation and length: nothing here reinterprets what the operator wrote.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path

from ..core.database import open_database, utc_now
from ..core.text import sanitize_text

MAX_NOTE_CHARS = 4000
MAX_LISTED = 20
TARGET_KINDS = ("topology_node", "topology_edge", "engagement")


class NoteError(ValueError):
    """A note that cannot be stored or read, with the reason in the sentence."""


@dataclass(frozen=True)
class Note:
    id: str
    target_kind: str
    target_id: str
    body: str
    author: str
    created_at: str
    updated_at: str

    @property
    def summary(self) -> str:
        """First line, for a one-line slot in a panel."""
        first = self.body.strip().splitlines()[0] if self.body.strip() else ""
        return first[:120]


def _engagement_id(conn: sqlite3.Connection) -> str:
    row = conn.execute("SELECT id FROM engagement LIMIT 1").fetchone()
    if row is None:
        raise NoteError("engagement database has no engagement row")
    return str(row[0])


def _clean(body: str) -> str:
    text = sanitize_text(body).strip()
    if not text:
        raise NoteError("a note needs some text")
    if len(text) > MAX_NOTE_CHARS:
        raise NoteError(f"a note is limited to {MAX_NOTE_CHARS} characters")
    return text


def add_note(
    database: str | Path,
    *,
    target_kind: str,
    target_id: str,
    body: str,
    author: str,
) -> Note:
    """Store a note. Notes are append-only: editing creates a new row."""
    if target_kind not in TARGET_KINDS:
        raise NoteError(f"unknown note target: {target_kind}")
    if target_kind != "engagement" and not target_id:
        raise NoteError("a note on a node or edge needs an id")
    text = _clean(body)
    stamp = utc_now()
    note_id = str(uuid.uuid4())
    conn = open_database(database)
    try:
        engagement = _engagement_id(conn)
        with conn:
            conn.execute(
                "INSERT INTO notes (id, engagement_id, target_kind, target_id,"
                " body_markdown, author, created_at, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (note_id, engagement, target_kind, target_id, text,
                 sanitize_text(author)[:80] or "operator", stamp, stamp),
            )
    finally:
        conn.close()
    return Note(note_id, target_kind, target_id, text, author, stamp, stamp)


def notes_for(
    database: str | Path,
    *,
    target_kind: str = "",
    target_id: str = "",
    limit: int = MAX_LISTED,
) -> tuple[Note, ...]:
    """Newest first, optionally narrowed to one target."""
    if limit < 1:
        raise NoteError("limit must be at least 1")
    clauses: list[str] = []
    values: list[str] = []
    if target_kind:
        clauses.append("target_kind = ?")
        values.append(target_kind)
    if target_id:
        clauses.append("COALESCE(target_id, '') = ?")
        values.append(target_id)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    conn = open_database(database, readonly=True)
    try:
        rows = conn.execute(
            "SELECT id, target_kind, COALESCE(target_id, ''), body_markdown, author,"
            " created_at, updated_at FROM notes"
            f"{where} ORDER BY updated_at DESC, id DESC LIMIT ?",
            (*values, limit),
        ).fetchall()
    finally:
        conn.close()
    return tuple(
        Note(str(row[0]), str(row[1]), str(row[2]), str(row[3]), str(row[4]),
             str(row[5]), str(row[6]))
        for row in rows
    )


def latest_note(database: str | Path, target_kind: str, target_id: str) -> Note | None:
    found = notes_for(database, target_kind=target_kind, target_id=target_id, limit=1)
    return found[0] if found else None