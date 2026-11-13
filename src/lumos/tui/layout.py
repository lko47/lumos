"""Deterministic topology placement and a pan/zoom viewport.

Placement is stable across redraws and across new discoveries: a node's angle
is derived from a hash of its identifier, so adding hosts never shuffles the
nodes already on screen.  Collisions inside a ring are resolved with a
deterministic linear probe.
"""

from __future__ import annotations

import hashlib
import math
from dataclasses import dataclass, replace
from typing import Iterable, Mapping, Protocol


class LayoutNode(Protocol):
    """The minimum node shape the layout needs."""

    @property
    def id(self) -> str: ...

    @property
    def kind(self) -> str: ...

    @property
    def distance(self) -> int: ...

Point = tuple[int, int]

# Terminal cells are roughly twice as tall as they are wide; the ellipse
# factor keeps rings visually circular.
ASPECT_X = 1.9
MIN_LABEL_COLUMNS = 14


def stable_slot(node_id: str, slot_count: int) -> int:
    """Map an identifier to a ring slot without Python's salted ``hash``."""
    if slot_count <= 0:
        return 0
    digest = hashlib.blake2b(node_id.encode("utf-8", "replace"), digest_size=8).digest()
    return int.from_bytes(digest, "big") % slot_count


@dataclass(frozen=True)
class Placement:
    positions: dict[str, Point]
    radius: float


def compute_layout(
    nodes: Iterable[LayoutNode],
    width: int,
    height: int,
    *,
    overrides: Mapping[str, Point] | None = None,
) -> dict[str, Point]:
    """Place the root at the centre and every other node on its hop ring.

    ``nodes`` items expose ``id``, ``kind`` and ``distance``.  ``overrides``
    wins for identifiers whose position was previously stored.
    """
    nodes = tuple(nodes)
    if not nodes or width < 4 or height < 3:
        return {}
    root = next((node for node in nodes if node.kind == "root"), nodes[0])
    cx, cy = width // 2, height // 2
    positions: dict[str, Point] = {root.id: (cx, cy)}
    for node in nodes:
        if overrides and node.id in overrides:
            positions[node.id] = overrides[node.id]

    groups: dict[int, list[object]] = {}
    for node in nodes:
        if node.id == root.id or (overrides and node.id in overrides):
            continue
        groups.setdefault(max(1, int(node.distance)), []).append(node)
    if not groups:
        return positions

    # Radius available for the outermost ring, leaving room for labels.
    max_y = max(1.0, height / 2.0 - 1.5)
    max_x = max(1.0, width / 2.0 / ASPECT_X - 1.0)
    outer = min(max_x, max_y)
    max_distance = max(groups)

    for distance, group in sorted(groups.items()):
        ring = outer * distance / max_distance
        ring = max(1.0, ring)
        circumference_x = 2.0 * math.pi * ring * ASPECT_X
        slots = max(len(group), int(circumference_x / MIN_LABEL_COLUMNS))
        taken: set[int] = set()
        for node in sorted(group, key=lambda item: item.id):
            slot = stable_slot(node.id, slots)
            for _ in range(slots):
                if slot not in taken:
                    break
                slot = (slot + 1) % slots
            taken.add(slot)
            angle = 2.0 * math.pi * slot / slots - math.pi / 2.0
            x = cx + round(math.cos(angle) * ring * ASPECT_X)
            y = cy + round(math.sin(angle) * ring)
            positions[node.id] = (max(1, min(width - 2, x)), max(1, min(height - 2, y)))
    return positions


ZOOM_LEVELS = (1.0, 1.25, 1.5, 2.0, 2.5, 3.0, 4.0, 6.0, 8.0)


@dataclass(frozen=True)
class Viewport:
    """A zoom/pan transform between world cells and the map panel."""

    zoom: float = 1.0
    pan_x: int = 0
    pan_y: int = 0

    def project(self, point: Point, width: int, height: int) -> Point:
        cx, cy = width / 2.0, height / 2.0
        return (
            round((point[0] - cx) * self.zoom + cx + self.pan_x),
            round((point[1] - cy) * self.zoom + cy + self.pan_y),
        )

    def unproject(self, point: Point, width: int, height: int) -> Point:
        cx, cy = width / 2.0, height / 2.0
        return (
            round((point[0] - cx - self.pan_x) / self.zoom + cx),
            round((point[1] - cy - self.pan_y) / self.zoom + cy),
        )

    def visible(self, point: Point, width: int, height: int, margin: int = 1) -> bool:
        x, y = self.project(point, width, height)
        return -margin <= x <= width + margin and -margin <= y <= height + margin

    def pan(self, dx: int, dy: int, width: int, height: int) -> "Viewport":
        limit_x = max(2, width)
        limit_y = max(2, height)
        return replace(
            self,
            pan_x=max(-limit_x, min(limit_x, self.pan_x + dx)),
            pan_y=max(-limit_y, min(limit_y, self.pan_y + dy)),
        )

    def _level_index(self) -> int:
        if self.zoom in ZOOM_LEVELS:
            return ZOOM_LEVELS.index(self.zoom)
        return min(range(len(ZOOM_LEVELS)), key=lambda index: abs(ZOOM_LEVELS[index] - self.zoom))

    def zoom_in(self) -> "Viewport":
        return replace(self, zoom=ZOOM_LEVELS[min(self._level_index() + 1, len(ZOOM_LEVELS) - 1)])

    def zoom_out(self) -> "Viewport":
        return replace(self, zoom=ZOOM_LEVELS[max(self._level_index() - 1, 0)])

    def zoom_to(
        self,
        level: float,
        width: int,
        height: int,
        anchor: Point | None = None,
    ) -> "Viewport":
        """Zoom to ``level`` keeping the world point under ``anchor`` still.

        ``anchor`` is panel-local; the default is the panel centre, which is
        what the keyboard zoom keys use. Pan is recomputed so the anchor does
        not drift, which is what makes wheel-zoom at the cursor feel stable.
        """
        ax, ay = anchor if anchor is not None else (width / 2.0, height / 2.0)
        world_x, world_y = self.unproject((round(ax), round(ay)), width, height)
        cx, cy = width / 2.0, height / 2.0
        return replace(
            self,
            zoom=level,
            pan_x=round(ax - cx - (world_x - cx) * level),
            pan_y=round(ay - cy - (world_y - cy) * level),
        )

    def zoom_at(self, x: int, y: int, width: int, height: int, direction: int) -> "Viewport":
        """Zoom one level in (``direction`` > 0) or out, anchored at ``x, y``."""
        index = self._level_index()
        step = 1 if direction > 0 else -1
        level = ZOOM_LEVELS[max(0, min(len(ZOOM_LEVELS) - 1, index + step))]
        return self.zoom_to(level, width, height, (x, y))

    def reset(self) -> "Viewport":
        return Viewport()

    @property
    def label(self) -> str:
        if self.pan_x or self.pan_y:
            return f"zoom {self.zoom:.2f}x pan {self.pan_x:+d},{self.pan_y:+d}"
        return f"zoom {self.zoom:.2f}x"
