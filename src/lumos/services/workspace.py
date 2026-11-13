"""Several engagement files in one view, each drawn as its own cluster.

An assessment often spans sites: what one vantage point saw and what another
saw are separate evidence, so nothing is merged on disk.  A workspace keeps
each file byte-identical, tags every node with the file it came from, and adds
*shared-address* links between clusters so the same host seen twice is visible
as one host seen twice rather than as two unrelated machines.

Nothing here writes: openings are read-only, and the loader is bounded.
"""

from __future__ import annotations

import sqlite3
from dataclasses import dataclass, replace
from pathlib import Path

from .map_view import MapEdge, MapSnapshot, MapNode, load_map_snapshot

MAX_MEMBERS = 8
MAX_BRIDGES = 128
SHARED_EDGE = "shared"
WORKSPACE_SEPARATOR = "."


@dataclass(frozen=True)
class WorkspaceMember:
    """One engagement file in the workspace."""

    path: str
    tag: str
    name: str
    scans: int = 0
    review_items: int = 0

    @property
    def label(self) -> str:
        return f"{self.tag} {self.name}"


def engagement_name(path: str | Path) -> str:
    """Read the engagement name without writing; fall back to the file name."""
    target = Path(path)
    try:
        connection = sqlite3.connect(f"file:{target}?mode=ro", uri=True)
        try:
            row = connection.execute("SELECT name FROM engagement LIMIT 1").fetchone()
        finally:
            connection.close()
    except (sqlite3.Error, OSError):
        return target.stem
    return str(row[0]) if row and row[0] else target.stem


def describe(path: str | Path, tag: str) -> WorkspaceMember:
    return WorkspaceMember(path=str(path), tag=tag, name=engagement_name(path))


def members_for(paths: list[str] | tuple[str, ...]) -> tuple[WorkspaceMember, ...]:
    """Tag the first ``MAX_MEMBERS`` files; later ones are ignored, not merged."""
    unique: list[str] = []
    for path in paths:
        resolved = str(Path(path))
        if resolved not in unique:
            unique.append(resolved)
    return tuple(
        describe(path, f"s{index + 1}") for index, path in enumerate(unique[:MAX_MEMBERS])
    )


def _tag(snapshot: MapSnapshot, member: WorkspaceMember) -> tuple[list[MapNode], list[MapEdge]]:
    """Prefix every id so two files can never collide, and mark the source."""
    prefix = f"{member.tag}{WORKSPACE_SEPARATOR}"
    nodes = [
        replace(
            node,
            id=prefix + node.id,
            source_tag=member.tag,
            label=f"[{member.name}] {node.label}" if node.kind == "root" else node.label,
        )
        for node in snapshot.nodes
    ]
    edges = [
        replace(
            edge,
            id=prefix + edge.id,
            from_node_id=prefix + edge.from_node_id,
            to_node_id=prefix + edge.to_node_id,
            source_tag=member.tag,
        )
        for edge in snapshot.edges
    ]
    return nodes, edges


def _bridges(parts: list[tuple[list[MapNode], list[MapEdge], WorkspaceMember]]) -> list[MapEdge]:
    """Link clusters where the same address was seen from more than one vantage.

    These are *not* traffic edges: they say "this address appeared in two
    engagements", which is the only claim two independent files support.
    """
    seen: dict[str, list[MapNode]] = {}
    for nodes, _edges, _member in parts:
        for node in nodes:
            for address in node.addresses:
                seen.setdefault(address.lower(), []).append(node)
    bridges: list[MapEdge] = []
    for address in sorted(seen):
        group = seen[address]
        if len({node.source_tag for node in group}) < 2:
            continue
        anchor = group[0]
        for node in group[1:]:
            if node.source_tag == anchor.source_tag:
                continue
            bridges.append(
                MapEdge(
                    id=f"bridge:{anchor.id}~{node.id}",
                    from_node_id=anchor.id,
                    to_node_id=node.id,
                    edge_type=SHARED_EDGE,
                    source_kind="workspace",
                    source_id=address,
                    confidence=1.0,
                    first_observed_at="",
                    last_confirmed_at="",
                    author="workspace",
                    bridge=True,
                )
            )
            if len(bridges) >= MAX_BRIDGES:
                return bridges
    return bridges


def load_workspace_snapshot(
    paths: list[str] | tuple[str, ...],
    *,
    max_nodes: int = 2000,
    expanded_zone: str = "",
) -> MapSnapshot:
    """Load and combine engagement files into one bounded, read-only snapshot."""
    members = members_for(paths)
    parts: list[tuple[list[MapNode], list[MapEdge], WorkspaceMember]] = []
    counts: list[WorkspaceMember] = []
    for member in members:
        snapshot = load_map_snapshot(member.path, max_nodes=max_nodes, expanded_zone=expanded_zone)
        nodes, edges = _tag(snapshot, member)
        counts.append(
            replace(member, scans=snapshot.scans, review_items=snapshot.review_items)
        )
        parts.append((nodes, edges, member))

    nodes = [node for part in parts for node in part[0]]
    edges = [edge for part in parts for edge in part[1]]
    edges.extend(_bridges(parts))
    hidden = max(0, len(nodes) - max_nodes)
    name = " + ".join(member.name for member in counts) if counts else "workspace"
    return MapSnapshot(
        engagement_id="workspace",
        engagement_name=name,
        scans=sum(member.scans for member in counts),
        active_scans=0,
        review_items=sum(member.review_items for member in counts),
        nodes=tuple(nodes[:max_nodes]),
        edges=tuple(edges),
        root_label=f"{len(counts)} engagement(s)",
        not_shown=hidden,
        expanded_zone=expanded_zone,
        members=tuple((member.tag, member.name) for member in counts),
    )


def shared_address_count(snapshot: MapSnapshot) -> int:
    """How many cross-file links the snapshot carries (for the status line)."""
    return sum(1 for edge in snapshot.edges if edge.bridge)