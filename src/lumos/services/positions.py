"""Pinned node positions, stored as fractions of the map panel.

Fractions, not grid cells: a pin is a statement about where a node belongs
relative to the picture, so it must survive a resize, a zoom or a different
terminal. The database table has held x/y since schema v2 and nothing wrote it.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path

from ..core.database import open_database, utc_now
from ..core.text import sanitize_text

DEFAULT_LAYOUT = "default"


class PositionError(ValueError):
    """A pin that cannot be stored, with the reason in the sentence."""


@dataclass(frozen=True)
class Pin:
    node_id: str
    x: float
    y: float


def _check(value: float, axis: str) -> float:
    if not math.isfinite(value) or not 0.0 <= value <= 1.0:
        raise PositionError(f"a pinned {axis} must be between 0 and 1")
    return float(value)


def load_pins(
    database: str | Path, layout_key: str = DEFAULT_LAYOUT
) -> dict[str, tuple[float, float]]:
    """node id -> (x fraction, y fraction) for every pinned node."""
    conn = open_database(database, readonly=True)
    try:
        rows = conn.execute(
            "SELECT topology_node_id, x, y FROM node_positions"
            " WHERE layout_key = ? AND pinned = 1",
            (layout_key,),
        ).fetchall()
    finally:
        conn.close()
    return {str(row[0]): (float(row[1]), float(row[2])) for row in rows}


def pin_node(
    database: str | Path,
    *,
    node_id: str,
    x: float,
    y: float,
    author: str,
    layout_key: str = DEFAULT_LAYOUT,
) -> Pin:
    """Store a pin, replacing any earlier one for this node and layout."""
    if not node_id:
        raise PositionError("a pin needs a node id")
    clean_x, clean_y = _check(x, "x"), _check(y, "y")
    stamp = utc_now()
    conn = open_database(database)
    try:
        with conn:
            exists = conn.execute(
                "SELECT 1 FROM topology_nodes WHERE id = ?", (node_id,)
            ).fetchone()
            if exists is None:
                raise PositionError(f"no topology node with id {node_id}")
            conn.execute(
                "INSERT INTO node_positions"
                " (topology_node_id, layout_key, x, y, pinned, grid_x, grid_y, updated_at, author)"
                " VALUES (?, ?, ?, ?, 1, 0, 0, ?, ?)"
                " ON CONFLICT(topology_node_id, layout_key) DO UPDATE SET"
                " x = excluded.x, y = excluded.y, pinned = 1,"
                " updated_at = excluded.updated_at, author = excluded.author",
                (node_id, layout_key, clean_x, clean_y, stamp,
                 sanitize_text(author)[:80] or "operator"),
            )
    finally:
        conn.close()
    return Pin(node_id, clean_x, clean_y)


def unpin_node(
    database: str | Path, node_id: str, layout_key: str = DEFAULT_LAYOUT
) -> bool:
    """Drop a pin; True when one was there. The row stays, `pinned` goes to 0."""
    conn = open_database(database)
    try:
        with conn:
            cursor = conn.execute(
                "UPDATE node_positions SET pinned = 0, updated_at = ?"
                " WHERE topology_node_id = ? AND layout_key = ? AND pinned = 1",
                (utc_now(), node_id, layout_key),
            )
            return cursor.rowcount > 0
    finally:
        conn.close()


def overrides_for(
    pins: dict[str, tuple[float, float]], width: int, height: int
) -> dict[str, tuple[int, int]]:
    """Convert fractions to grid cells for the current panel size."""
    if width < 2 or height < 2:
        return {}
    return {
        node_id: (
            min(width - 1, max(0, round(x * (width - 1)))),
            min(height - 1, max(0, round(y * (height - 1)))),
        )
        for node_id, (x, y) in pins.items()
    }


def _normalise(position: tuple[int, int], width: int, height: int) -> tuple[float, float]:
    x, y = position
    return (x / (width - 1) if width > 1 else 0.0, y / (height - 1) if height > 1 else 0.0)


def fraction_at(position: tuple[int, int], width: int, height: int) -> tuple[float, float]:
    """Public alias: a grid cell as the fractions a pin stores."""
    return _normalise(position, width, height)
