"""Read-only snapshots for the topology map and host list."""

from __future__ import annotations

import json
import queue
import threading
from collections import deque
from dataclasses import dataclass
from pathlib import Path

from ..core.database import DatabaseError, open_database
from ..core.text import sanitize_text


@dataclass(frozen=True)
class MapNode:
    id: str
    kind: str
    label: str
    addresses: tuple[str, ...]
    os_name: str
    open_ports: int
    review_count: int
    distance: int
    ports: tuple[str, ...] = ()


@dataclass(frozen=True)
class MapEdge:
    id: str
    from_node_id: str
    to_node_id: str
    edge_type: str
    source_kind: str
    source_id: str
    confidence: float
    first_observed_at: str
    last_confirmed_at: str
    author: str


@dataclass(frozen=True)
class ScanInfo:
    """One stored scan row for the live scan-status panel."""

    id: str
    status: str
    targets: tuple[str, ...]
    started_at: str
    ended_at: str
    exit_code: int | None
    operator: str
    interface: str
    nmap_version: str
    hosts: int

    @property
    def short_id(self) -> str:
        return self.id[:8]


@dataclass(frozen=True)
class MapSnapshot:
    engagement_id: str
    engagement_name: str
    scans: int
    active_scans: int
    review_items: int
    nodes: tuple[MapNode, ...]
    edges: tuple[MapEdge, ...]
    scans_detail: tuple[ScanInfo, ...] = ()
    root_label: str = ""
    root_interfaces: tuple[str, ...] = ()


def load_map_snapshot(database: str | Path, *, max_nodes: int = 2000) -> MapSnapshot:
    """Load a bounded read-only map snapshot; disconnected nodes stay unlinked."""
    if max_nodes < 1:
        raise ValueError("max_nodes must be at least 1")
    conn = open_database(database, readonly=True)
    try:
        engagement = conn.execute("SELECT id, name FROM engagement LIMIT 1").fetchone()
        if engagement is None:
            raise DatabaseError("engagement database has no engagement row")
        engagement_id, engagement_name = engagement
        rows = conn.execute(
            """WITH latest AS (
                   SELECT h.* FROM host_observations h
                   WHERE h.id = (
                       SELECT h2.id FROM host_observations h2
                       WHERE h2.device_id = h.device_id
                       ORDER BY h2.observed_at DESC, h2.id DESC LIMIT 1
                   )
               ), address_text AS (
                   SELECT host_observation_id, group_concat(display_value, ', ') AS addresses
                   FROM (
                       SELECT DISTINCT oa.host_observation_id, a.display_value
                       FROM observation_addresses oa
                       JOIN addresses a ON a.id = oa.address_id
                   ) GROUP BY host_observation_id
               ), port_counts AS (
                   SELECT host_observation_id, SUM(CASE WHEN state = 'open' THEN 1 ELSE 0 END) AS open_ports
                   FROM port_observations GROUP BY host_observation_id
               )
               SELECT tn.id, tn.kind, tn.label, tn.entity_id,
                      COALESCE(l.hostname, '') AS hostname,
                      COALESCE(l.os_name, '') AS os_name,
                      COALESCE(a.addresses, '') AS addresses,
                      COALESCE(pc.open_ports, 0) AS open_ports,
                      COALESCE(th.address_text, '') AS hop_address,
                      COALESCE((SELECT group_concat(p.port || '/' || p.protocol, ' ')
                                FROM port_observations p
                                WHERE p.host_observation_id = l.id AND p.state = 'open'), '') AS ports,
                      (SELECT COUNT(*) FROM review_items ri
                       WHERE ri.engagement_id = tn.engagement_id
                         AND ((ri.target_kind = 'topology_node' AND ri.target_id = tn.id)
                           OR (ri.target_kind = 'device' AND ri.target_id = tn.entity_id))
                         AND (SELECT re.state FROM review_events re WHERE re.review_item_id = ri.id
                              ORDER BY re.created_at DESC, re.id DESC LIMIT 1)
                             IN ('unreviewed', 'flagged', 'out_of_scope')) AS review_count
               FROM topology_nodes tn
               LEFT JOIN latest l ON tn.kind = 'device' AND l.device_id = tn.entity_id
               LEFT JOIN address_text a ON a.host_observation_id = l.id
               LEFT JOIN port_counts pc ON pc.host_observation_id = l.id
               LEFT JOIN trace_hops th ON tn.kind IN ('hop', 'unknown_hop') AND th.id = tn.entity_id
               WHERE tn.engagement_id = ?
               ORDER BY CASE tn.kind WHEN 'root' THEN 0 WHEN 'hop' THEN 1 WHEN 'unknown_hop' THEN 2 ELSE 3 END,
                        lower(COALESCE(l.hostname, tn.label)), tn.id
               LIMIT ?""",
            (engagement_id, max_nodes),
        ).fetchall()

        edges = tuple(
            MapEdge(
                id=str(row[0]),
                from_node_id=str(row[1]),
                to_node_id=str(row[2]),
                edge_type=sanitize_text(row[3], max_chars=64),
                source_kind=sanitize_text(row[4], max_chars=64),
                source_id=sanitize_text(row[5] or "", max_chars=128),
                confidence=float(row[6]),
                first_observed_at=sanitize_text(row[7], max_chars=64),
                last_confirmed_at=sanitize_text(row[8] or "", max_chars=64),
                author=sanitize_text(row[9] or "", max_chars=128),
            )
            for row in conn.execute(
                "SELECT id, from_node_id, to_node_id, edge_type, source_kind, source_id, confidence, "
                "first_observed_at, last_confirmed_at, author FROM topology_edges "
                "WHERE engagement_id = ? ORDER BY first_observed_at, id LIMIT ?",
                (engagement_id, max_nodes * 2),
            )
            if row[1] and row[2]
        )
        nodes: list[MapNode] = []
        node_ids: set[str] = set()
        root_ids: list[str] = []
        for row in rows:
            node_id = str(row[0])
            node_ids.add(node_id)
            kind = str(row[1])
            if kind == "root":
                root_ids.append(node_id)
            base_label = row[4] if kind == "device" and row[4] else row[8] if kind in {"hop", "unknown_hop"} and row[8] else row[2]
            label = sanitize_text(base_label or kind.replace("_", " "), max_chars=120)
            addresses = tuple(
                sanitize_text(item, max_chars=128)
                for item in str(row[6]).split(", ")
                if item
            )
            nodes.append(
                MapNode(
                    id=node_id,
                    kind=kind,
                    label=label,
                    addresses=addresses,
                    os_name=sanitize_text(row[5], max_chars=256),
                    open_ports=int(row[7] or 0),
                    review_count=int(row[10] or 0),
                    distance=0,
                    ports=tuple(
                        sanitize_text(item, max_chars=16)
                        for item in str(row[9]).split(" ")
                        if item
                    )[:16],
                )
            )

        # Do not fabricate connectivity: an isolated host remains a marker without an edge.
        adjacency: dict[str, set[str]] = {node_id: set() for node_id in node_ids}
        for edge in edges:
            if edge.from_node_id in node_ids and edge.to_node_id in node_ids:
                adjacency[edge.from_node_id].add(edge.to_node_id)
                adjacency[edge.to_node_id].add(edge.from_node_id)
        distances: dict[str, int] = {}
        queue_ids: deque[str] = deque()
        for root_id in root_ids:
            distances[root_id] = 0
            queue_ids.append(root_id)
        while queue_ids:
            current = queue_ids.popleft()
            for neighbor in adjacency[current]:
                if neighbor not in distances:
                    distances[neighbor] = distances[current] + 1
                    queue_ids.append(neighbor)
        if not root_ids:
            # An empty engagement gets an explicit placeholder root, not a persisted scanner claim.
            nodes.insert(
                0,
                MapNode("pending-root", "root", "Scanner not yet recorded", (), "", 0, 0, 0),
            )
        nodes = [
            MapNode(n.id, n.kind, n.label, n.addresses, n.os_name, n.open_ports, n.review_count,
                    distances.get(n.id, 2 if n.kind != "root" else 0), n.ports)
            for n in nodes
        ]
        scans = conn.execute("SELECT COUNT(*) FROM scans WHERE engagement_id = ?", (engagement_id,)).fetchone()[0]
        active_scans = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE engagement_id = ? AND status = 'running'", (engagement_id,)
        ).fetchone()[0]
        reviews = conn.execute(
            "SELECT COUNT(*) FROM review_items r WHERE r.engagement_id = ? AND "
            "(SELECT e.state FROM review_events e WHERE e.review_item_id = r.id "
            "ORDER BY e.created_at DESC, e.id DESC LIMIT 1) IN ('unreviewed', 'flagged', 'out_of_scope')",
            (engagement_id,),
        ).fetchone()[0]
        root_row = conn.execute(
            "SELECT tn.id, tn.label, COALESCE(vp.scanner_name, ''), tn.entity_id "
            "FROM topology_nodes tn LEFT JOIN vantage_points vp ON vp.id = tn.entity_id "
            "WHERE tn.engagement_id = ? AND tn.kind = 'root' "
            "ORDER BY tn.created_at, tn.id LIMIT 1",
            (engagement_id,),
        ).fetchone()
        root_label = ""
        root_interfaces: list[str] = []
        if root_row is not None:
            root_label = sanitize_text(root_row[2] or root_row[1] or "scanner", max_chars=120)
            if root_row[3]:
                for interface in conn.execute(
                    "SELECT name, address FROM vantage_interfaces "
                    "WHERE vantage_point_id = ? ORDER BY name, address LIMIT 24",
                    (root_row[3],),
                ):
                    name = sanitize_text(interface[0], max_chars=32)
                    address = sanitize_text(interface[1], max_chars=64)
                    if name and address:
                        root_interfaces.append(f"{name} {address}")
                    elif name or address:
                        root_interfaces.append(name or address)
        scans_detail: list[ScanInfo] = []
        for row in conn.execute(
            "SELECT s.id, s.status, s.targets_json, s.started_at, COALESCE(s.ended_at, ''), "
            "s.exit_code, s.operator, s.interface, s.nmap_version, "
            "(SELECT COUNT(*) FROM host_observations h WHERE h.scan_id = s.id) "
            "FROM scans s WHERE s.engagement_id = ? "
            "ORDER BY s.started_at DESC, s.id DESC LIMIT 25",
            (engagement_id,),
        ):
            try:
                targets = json.loads(row[2]) if row[2] else []
            except (TypeError, ValueError):
                targets = []
            if isinstance(targets, dict):
                targets = targets.get("requested") or targets.get("resolved") or []
            if not isinstance(targets, list):
                targets = []
            targets = [str(item) for item in targets]
            scans_detail.append(
                ScanInfo(
                    id=str(row[0]),
                    status=sanitize_text(row[1], max_chars=16),
                    targets=tuple(sanitize_text(item, max_chars=64) for item in targets[:8]),
                    started_at=sanitize_text(row[3], max_chars=32),
                    ended_at=sanitize_text(row[4], max_chars=32),
                    exit_code=row[5],
                    operator=sanitize_text(row[6], max_chars=64),
                    interface=sanitize_text(row[7], max_chars=32),
                    nmap_version=sanitize_text(row[8], max_chars=64),
                    hosts=int(row[9] or 0),
                )
            )
        return MapSnapshot(
            engagement_id=str(engagement_id),
            engagement_name=sanitize_text(engagement_name, max_chars=512),
            scans=int(scans),
            active_scans=int(active_scans),
            review_items=int(reviews),
            nodes=tuple(nodes),
            edges=tuple(edge for edge in edges if edge.from_node_id in node_ids and edge.to_node_id in node_ids),
            scans_detail=tuple(scans_detail),
            root_label=root_label,
            root_interfaces=tuple(root_interfaces),
        )
    finally:
        conn.close()


class MapSnapshotWatcher:
    """Watch another database connection's commits and publish fresh snapshots."""

    def __init__(self, database: str | Path, *, interval: float = 1.0):
        if interval <= 0:
            raise ValueError("watch interval must be positive")
        self.database = Path(database)
        self.interval = interval
        self._stop = threading.Event()
        self._updates: queue.Queue[MapSnapshot] = queue.Queue(maxsize=1)
        self._error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, name="lumos-map-watcher", daemon=True)

    @property
    def error(self) -> BaseException | None:
        return self._error

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=6.0)

    def take_latest(self) -> MapSnapshot | None:
        latest = None
        while True:
            try:
                latest = self._updates.get_nowait()
            except queue.Empty:
                return latest

    def _publish(self, snapshot: MapSnapshot) -> None:
        try:
            self._updates.put_nowait(snapshot)
        except queue.Full:
            try:
                self._updates.get_nowait()
            except queue.Empty:
                pass
            try:
                self._updates.put_nowait(snapshot)
            except queue.Full:
                pass

    def _run(self) -> None:
        conn = None
        try:
            conn = open_database(self.database, readonly=True)
            version = int(conn.execute("PRAGMA data_version").fetchone()[0])
            while not self._stop.wait(self.interval):
                current = int(conn.execute("PRAGMA data_version").fetchone()[0])
                if current != version:
                    version = current
                    self._publish(load_map_snapshot(self.database))
        except Exception as exc:
            self._error = exc
        finally:
            if conn is not None:
                conn.close()


def render_plain_snapshot(snapshot: MapSnapshot) -> str:
    """Produce a stable non-interactive fallback without requiring a terminal."""
    lines = [
        f"Lumos - {sanitize_text(snapshot.engagement_name, max_chars=256)}",
        f"Scans: {snapshot.scans} | Active: {snapshot.active_scans} | Nodes: {len(snapshot.nodes)} | Review: {snapshot.review_items}",
    ]
    for node in snapshot.nodes:
        addresses = ", ".join(node.addresses) if node.addresses else ""
        details = f" [{addresses}]" if addresses else ""
        if node.kind == "device":
            details += f" - {node.open_ports} open ports"
        line = f"{node.kind:12} {node.label}{details}"
        lines.append(sanitize_text(line, max_chars=512))
    if not snapshot.edges:
        lines.append("No topology links recorded; disconnected nodes are not connected by inference.")
    else:
        by_id = {node.id: node for node in snapshot.nodes}
        for edge in snapshot.edges:
            source = f"{edge.source_kind}:{edge.source_id}" if edge.source_id else edge.source_kind
            first = edge.first_observed_at or "unknown"
            confirmed = edge.last_confirmed_at or "not reconfirmed"
            lines.append(
                f"Link {by_id[edge.from_node_id].label} -> {by_id[edge.to_node_id].label}: "
                f"{edge.edge_type}, source {source}, confidence {edge.confidence:.2f}, "
                f"first {first}, last confirmed {confirmed}"
            )
    return "\n".join(lines) + "\n"
