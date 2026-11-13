"""The review queue: items that need a human decision, and their history.

A review item is append-only in spirit: every decision is a new event and the
item's current state is the newest event. Rewriting history would make an audit
trail that agrees with whoever wrote last, which is not an audit trail.
"""

from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path

from ..core.database import open_database, utc_now
from ..core.text import sanitize_text

MAX_LISTED = 100

DECIDED_STATES = ("confirmed", "ignored", "flagged", "out_of_scope")
ALL_STATES = ("unreviewed", *DECIDED_STATES)

_LATEST_STATE = (
    "COALESCE((SELECT e.state FROM review_events e WHERE e.review_item_id = r.id"
    " ORDER BY e.created_at DESC, e.rowid DESC LIMIT 1), 'unreviewed')"
)


class ReviewError(ValueError):
    """A review action that cannot be taken, with the reason in the sentence."""


@dataclass(frozen=True)
class ReviewItem:
    id: str
    target_kind: str
    target_id: str
    reason_code: str
    reason_detail: str
    state: str
    created_at: str

    @property
    def short_summary(self) -> str:
        """A list row that fits a dialog: ids are shortened, not dropped."""
        identity = self.target_id if len(self.target_id) <= 10 else self.target_id[:8] + "…"
        return f"{self.reason_code} [{self.state}] {self.target_kind} {identity}"

    @property
    def summary(self) -> str:
        """One line for a list: the code, the target and the current state."""
        detail = f" - {self.reason_detail}" if self.reason_detail else ""
        return f"{self.reason_code} [{self.state}] {self.target_kind}:{self.target_id}{detail}"


def list_items(
    database: str | Path, *, limit: int = 20, state: str = ""
) -> tuple[ReviewItem, ...]:
    """Newest first, optionally filtered to one state."""
    if limit < 1 or limit > MAX_LISTED:
        raise ReviewError(f"limit must be between 1 and {MAX_LISTED}")
    if state and state not in ALL_STATES:
        raise ReviewError(f"unknown review state: {state}")
    conn = open_database(database, readonly=True)
    try:
        rows = conn.execute(
            f"SELECT r.id, r.target_kind, r.target_id, r.reason_code, r.reason_detail,"
            f" {_LATEST_STATE} AS state, r.created_at"
            " FROM review_items r ORDER BY r.latest_event_at DESC, r.id DESC LIMIT ?",
            (MAX_LISTED,),
        ).fetchall()
    finally:
        conn.close()
    items = [
        ReviewItem(
            id=str(row[0]),
            target_kind=str(row[1]),
            target_id=str(row[2]),
            reason_code=str(row[3]),
            reason_detail=sanitize_text(row[4], max_chars=200),
            state=str(row[5]),
            created_at=str(row[6]),
        )
        for row in rows
    ]
    if state:
        items = [item for item in items if item.state == state]
    return tuple(items[:limit])


def states_of(database: str | Path) -> dict[str, int]:
    """Count of items per current state, every state present."""
    conn = open_database(database, readonly=True)
    try:
        rows = conn.execute(
            f"SELECT {_LATEST_STATE} AS state, COUNT(*) FROM review_items r GROUP BY state"
        ).fetchall()
    finally:
        conn.close()
    counts = {name: 0 for name in ALL_STATES}
    for name, count in rows:
        counts[str(name)] = int(count)
    return counts


def set_state(
    database: str | Path,
    item_id: str,
    state: str,
    *,
    author: str,
    detail: str = "",
) -> ReviewItem:
    """Record a decision as a new event and return the item as it now stands."""
    if state not in DECIDED_STATES:
        raise ReviewError(
            "a decision must be one of: " + ", ".join(DECIDED_STATES)
        )
    if not item_id:
        raise ReviewError("a decision needs a review item")
    stamp = utc_now()
    conn = open_database(database)
    try:
        with conn:
            row = conn.execute(
                "SELECT 1 FROM review_items WHERE id = ?", (item_id,)
            ).fetchone()
            if row is None:
                raise ReviewError(f"no review item with id {item_id}")
            conn.execute(
                "INSERT INTO review_events (id, review_item_id, state, reason_detail,"
                " author, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    item_id,
                    state,
                    sanitize_text(detail, max_chars=500),
                    sanitize_text(author, max_chars=80) or "operator",
                    stamp,
                ),
            )
            conn.execute(
                "UPDATE review_items SET latest_event_at = ? WHERE id = ?",
                (stamp, item_id),
            )
            item = _load(conn, item_id)
    finally:
        conn.close()
    if item is None:  # pragma: no cover - the row existed a moment ago
        raise ReviewError("the review item disappeared while it was being decided")
    return item


def _load(conn: sqlite3.Connection, item_id: str) -> ReviewItem | None:
    row = conn.execute(
        f"SELECT r.id, r.target_kind, r.target_id, r.reason_code, r.reason_detail,"
        f" {_LATEST_STATE} AS state, r.created_at FROM review_items r WHERE r.id = ?",
        (item_id,),
    ).fetchone()
    if row is None:
        return None
    return ReviewItem(
        id=str(row[0]),
        target_kind=str(row[1]),
        target_id=str(row[2]),
        reason_code=str(row[3]),
        reason_detail=sanitize_text(row[4], max_chars=200),
        state=str(row[5]),
        created_at=str(row[6]),
    )