"""Shortest visible path between two nodes, over stored edges only.

A path is a claim about connectivity, so it is never invented: it is a BFS over
the edges the current snapshot actually carries (and therefore over the zones
that are currently expanded). Collapsing a hub shortens the picture because the
database is not being reorganised - only what is drawn changes.
"""

from __future__ import annotations

from collections import deque

from .map_view import MapEdge, MapSnapshot

PATH_START = "start"
PATH_END = "end"


def adjacency(snapshot: MapSnapshot) -> dict[str, set[str]]:
    """Undirected adjacency for the visible graph."""
    graph: dict[str, set[str]] = {node.id: set() for node in snapshot.nodes}
    for edge in snapshot.edges:
        if edge.from_node_id in graph and edge.to_node_id in graph:
            graph[edge.from_node_id].add(edge.to_node_id)
            graph[edge.to_node_id].add(edge.from_node_id)
    return graph


def shortest_path(snapshot: MapSnapshot, start_id: str, end_id: str) -> tuple[str, ...]:
    """Node ids from start to end inclusive; empty when either is unknown."""
    if not start_id or not end_id:
        return ()
    graph = adjacency(snapshot)
    if start_id not in graph or end_id not in graph:
        return ()
    if start_id == end_id:
        return (start_id,)
    previous: dict[str, str] = {}
    seen = {start_id}
    queue: deque[str] = deque([start_id])
    while queue:
        current = queue.popleft()
        for neighbour in sorted(graph[current]):
            if neighbour in seen:
                continue
            previous[neighbour] = current
            if neighbour == end_id:
                trail = [end_id]
                while trail[-1] != start_id:
                    trail.append(previous[trail[-1]])
                return tuple(reversed(trail))
            seen.add(neighbour)
            queue.append(neighbour)
    return ()


def path_edge_ids(snapshot: MapSnapshot, path: tuple[str, ...]) -> frozenset[str]:
    """Ids of the edges whose endpoints are consecutive nodes on the path.

    Parallel edges (a measured link and an inferred one between the same pair)
    all light up: the path is about reachability, not about picking a favourite
    explanation for it.
    """
    if len(path) < 2:
        return frozenset()
    pairs = {frozenset((path[index], path[index + 1])) for index in range(len(path) - 1)}
    return frozenset(
        edge.id
        for edge in snapshot.edges
        if frozenset((edge.from_node_id, edge.to_node_id)) in pairs
    )


def hop_count(path: tuple[str, ...]) -> int:
    """Hops are edges, not nodes: a two-node path is one hop."""
    return max(0, len(path) - 1)


def describe(path: tuple[str, ...], labels: dict[str, str]) -> str:
    """One-line summary for the status bar: 'a -> b, 3 hops'."""
    if len(path) < 2:
        return ""
    first = labels.get(path[0], path[0])
    last = labels.get(path[-1], path[-1])
    return f"{first} -> {last}, {hop_count(path)} hop(s)"


def path_between(snapshot: MapSnapshot, start_id: str, end_id: str) -> tuple[tuple[str, ...], frozenset[str]]:
    """Convenience: the path and the edge ids to highlight, in one call."""
    path = shortest_path(snapshot, start_id, end_id)
    return path, path_edge_ids(snapshot, path)


def node_labels(snapshot: MapSnapshot) -> dict[str, str]:
    return {node.id: node.label for node in snapshot.nodes}


def existing_edge(snapshot: MapSnapshot, edge_id: str) -> MapEdge | None:
    for edge in snapshot.edges:
        if edge.id == edge_id:
            return edge
    return None