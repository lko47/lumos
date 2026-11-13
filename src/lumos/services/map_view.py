"""Read-only snapshots for the topology map and host list."""

from __future__ import annotations

import json
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass, field, replace
from pathlib import Path

from ..core.database import DatabaseError, open_database
from ..core.evidence import classify
from ..core.text import sanitize_text

# A hub with more members than this is drawn as one node with a count; asking
# for a host inside it expands it (that is the next feature), and the bounded
# query never materialises those member nodes at all.
_COLLAPSE_MEMBERS = 50



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
    member_count: int = 0
    assumed: bool = False
    placeholder: bool = False
    zone_id: str = ""
    ttl_hops: int | None = None
    duplicate_count: int = 1
    source_tag: str = ""


def ttl_hops(reason_ttl: int | None) -> int | None:
    """Estimate router hops from a status TTL, ignoring 0 and unknowns.

    The heuristic rounds the observed TTL up to the usual initial value and
    subtracts. It is a hint for the details panel, never a drawn edge.
    """
    if reason_ttl is None or int(reason_ttl) <= 0:
        return None
    value = int(reason_ttl)
    for initial in (32, 64, 128, 255):
        if value <= initial:
            return max(0, initial - value)
    return None


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
    rule: str = ""
    derived: bool = False
    evidence: dict = field(default_factory=dict)
    source_tag: str = ""
    bridge: bool = False


EDGE_CLASSES = ("local", "observed", "alternate", "likely", "weak", "manual")


def _evidence(raw: object) -> dict:
    """Parse stored evidence defensively; a malformed blob is not fatal."""
    if not raw:
        return {}
    try:
        parsed = json.loads(str(raw))
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def collapse_duplicates(
    nodes: list[MapNode], edges: tuple[MapEdge, ...]
) -> tuple[list[MapNode], tuple[MapEdge, ...]]:
    """Show one node per address set, without merging anything in the database.

    Devices are deliberately never auto-merged: the same host seen by three
    scans stays three device rows plus duplicate proposals, because merging by
    address alone can fuse two machines behind NAT.  The map, however, must not
    look like three machines.  This collapses device nodes that carry the same
    addresses onto the first one, keeps a duplicate count for the label, and
    rewrites edges so the graph stays consistent.
    """
    groups: dict[tuple[str, ...], MapNode] = {}
    aliases: dict[str, str] = {}
    collapsed: list[MapNode] = []
    counts: dict[str, int] = {}
    reviews: dict[str, int] = {}
    for node in nodes:
        key = tuple(sorted(address.lower() for address in node.addresses))
        if node.kind != "device" or not key:
            collapsed.append(node)
            continue
        first = groups.get(key)
        if first is None:
            groups[key] = node
            counts[node.id] = 1
            reviews[node.id] = node.review_count
            collapsed.append(node)
            continue
        aliases[node.id] = first.id
        counts[first.id] = counts.get(first.id, 1) + 1
        reviews[first.id] = reviews.get(first.id, 0) + node.review_count

    if not aliases:
        return nodes, edges

    collapsed = [
        replace(
            node,
            duplicate_count=counts.get(node.id, 1),
            review_count=reviews.get(node.id, node.review_count),
        )
        if node.id in counts
        else node
        for node in collapsed
    ]

    merged: dict[tuple[str, str, str], MapEdge] = {}
    for edge in edges:
        if edge.from_node_id == edge.to_node_id:
            continue
        source = aliases.get(edge.from_node_id, edge.from_node_id)
        target = aliases.get(edge.to_node_id, edge.to_node_id)
        if source == target:
            continue
        key = (source, target, edge.edge_type)
        merged.setdefault(key, replace(edge, from_node_id=source, to_node_id=target))
    return collapsed, tuple(merged.values())


def edge_class(edge: MapEdge) -> str:
    """Map a stored link to the evidence class the renderer draws.

    Confidence only splits inferred links: everything from 0.6 up is "likely"
    (dense dots), below that is "weak" (sparse dots). A guess can therefore
    never take a solid line.
    """
    return classify(edge.edge_type, edge.confidence)


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
    not_shown: int = 0
    expanded_zone: str = ""
    members: tuple[tuple[str, str], ...] = ()


def load_map_snapshot(
    database: str | Path, *, max_nodes: int = 2000, expanded_zone: str = ""
) -> MapSnapshot:
    """Load a bounded read-only map snapshot.

    The loader never invents links: every edge comes from ``topology_edges``.
    Hosts without traceroute data carry an ``inferred`` edge written at scan
    time, which the renderer draws with a dotted style and explicit provenance.
    """
    if max_nodes < 1:
        raise ValueError("max_nodes must be at least 1")
    conn = open_database(database, readonly=True)
    try:
        engagement = conn.execute("SELECT id, name FROM engagement LIMIT 1").fetchone()
        if engagement is None:
            raise DatabaseError("engagement database has no engagement row")
        engagement_id, engagement_name = engagement
        # Hubs above the collapse threshold are drawn as one node each, and
        # their member nodes are never selected. Grouping the hidden set once
        # is far cheaper than a correlated NOT IN over every device row.
        rows = conn.execute(
            """WITH big_zones AS (
                   SELECT zone_id FROM zone_memberships WHERE zone_id <> ?
                   GROUP BY zone_id HAVING COUNT(*) > ?
               ), hidden AS (
                   SELECT zm.topology_node_id AS node_id, 1 AS hidden
                   FROM zone_memberships zm
                   JOIN big_zones bz ON bz.zone_id = zm.zone_id
                   GROUP BY zm.topology_node_id
               ), chosen AS (
                   SELECT tn.id, tn.engagement_id, tn.kind, tn.label, tn.entity_id
                   FROM topology_nodes tn
                   LEFT JOIN hidden h ON h.node_id = tn.id
                   WHERE tn.engagement_id = ?
                     AND (tn.kind <> 'device' OR h.hidden IS NULL)
                     AND NOT (
                         tn.kind = 'zone'
                         AND EXISTS (SELECT 1 FROM zones z
                                     WHERE z.id = tn.entity_id AND z.zone_type = 'virtual')
                         AND NOT EXISTS (SELECT 1 FROM zone_memberships zm2
                                         WHERE zm2.zone_id = tn.entity_id)
                     )
                   ORDER BY CASE tn.kind WHEN 'root' THEN 0 WHEN 'zone' THEN 1
                             WHEN 'hop' THEN 2 WHEN 'unknown_hop' THEN 3 ELSE 4 END, tn.id
                   LIMIT ?
               ), chosen_devices AS (
                   SELECT entity_id AS device_id FROM chosen WHERE kind = 'device'
               ), latest AS (
                   SELECT h.* FROM host_observations h
                   JOIN chosen_devices cd ON cd.device_id = h.device_id
                   WHERE h.id = (
                       SELECT h2.id FROM host_observations h2
                       WHERE h2.device_id = h.device_id
                       ORDER BY h2.observed_at DESC, h2.id DESC LIMIT 1
                   )
               ), address_text AS (
                   SELECT oa.host_observation_id, group_concat(a.display_value, ', ') AS addresses
                   FROM observation_addresses oa
                   JOIN addresses a ON a.id = oa.address_id
                   WHERE oa.host_observation_id IN (SELECT id FROM latest)
                   GROUP BY oa.host_observation_id
               ), port_counts AS (
                   SELECT host_observation_id,
                          SUM(CASE WHEN state = 'open' THEN 1 ELSE 0 END) AS open_ports
                   FROM port_observations
                   WHERE host_observation_id IN (SELECT id FROM latest)
                   GROUP BY host_observation_id
               )
                              SELECT tn.id AS node_id,
                      tn.kind AS node_kind,
                      tn.label AS node_label,
                      tn.entity_id AS entity_id,
                      COALESCE(l.hostname, '') AS hostname,
                      l.reason_ttl AS reason_ttl,
                      COALESCE(l.os_name, '') AS os_name,
                      COALESCE(a.addresses, '') AS addresses,
                      COALESCE(pc.open_ports, 0) AS open_ports,
                      COALESCE(ha.display_value, '') AS hop_address,
                      (SELECT COUNT(*) FROM zone_memberships zm WHERE tn.kind = 'zone' AND zm.zone_id = tn.entity_id) AS members,
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
               FROM chosen tn
               LEFT JOIN latest l ON tn.kind = 'device' AND l.device_id = tn.entity_id
               LEFT JOIN address_text a ON a.host_observation_id = l.id
               LEFT JOIN port_counts pc ON pc.host_observation_id = l.id
               LEFT JOIN addresses ha ON tn.kind IN ('hop', 'unknown_hop') AND ha.id = tn.entity_id
               ORDER BY CASE tn.kind WHEN 'root' THEN 0 WHEN 'hop' THEN 1 WHEN 'unknown_hop' THEN 2 ELSE 3 END,
                        tn.id""",
            (expanded_zone, _COLLAPSE_MEMBERS, engagement_id, max_nodes),
        ).fetchall()

        # Only links whose *both* ends are visible belong on the map. A temp
        # table of the visible ids keeps this an indexed join; filtering after
        # the fact would materialise every link that leaves the scanner root.
        node_ids_in_rows = [str(row["node_id"]) for row in rows]
        conn.execute("CREATE TEMP TABLE IF NOT EXISTS visible_nodes(id TEXT PRIMARY KEY)")
        conn.execute("DELETE FROM visible_nodes")
        conn.executemany(
            "INSERT OR IGNORE INTO visible_nodes(id) VALUES (?)", ((node_id,) for node_id in node_ids_in_rows)
        )
        edge_rows = conn.execute(
            "SELECT e.id AS edge_id, e.from_node_id AS from_node_id, e.to_node_id AS to_node_id, "
            "e.edge_type AS edge_type, e.source_kind AS source_kind, e.source_id AS source_id, "
            "e.confidence AS confidence, e.first_observed_at AS first_observed_at, "
            "e.last_confirmed_at AS last_confirmed_at, e.author AS author, "
            "e.source_kind AS source_kind_rule, e.derived AS derived, e.evidence_json AS evidence_json "
            "FROM topology_edges e "
            "JOIN visible_nodes source_node ON source_node.id = e.from_node_id "
            "JOIN visible_nodes target_node ON target_node.id = e.to_node_id "
            "WHERE e.engagement_id = ? "
            "ORDER BY e.first_observed_at, e.id",
            (engagement_id,),
        ).fetchall()
        edges = tuple(
            MapEdge(
                id=str(row["edge_id"]),
                from_node_id=str(row["from_node_id"]),
                to_node_id=str(row["to_node_id"]),
                edge_type=sanitize_text(row["edge_type"], max_chars=64),
                source_kind=sanitize_text(row["source_kind"], max_chars=64),
                source_id=sanitize_text(row["source_id"] or "", max_chars=128),
                confidence=float(row["confidence"]),
                first_observed_at=sanitize_text(row["first_observed_at"], max_chars=64),
                last_confirmed_at=sanitize_text(row["last_confirmed_at"] or "", max_chars=64),
                author=sanitize_text(row["author"] or "", max_chars=128),
                rule=sanitize_text(str(row["source_kind_rule"] or "").removeprefix("rule:"), max_chars=64),
                derived=bool(row["derived"]),
                evidence=_evidence(row["evidence_json"]),
            )
            for row in edge_rows
            if row["from_node_id"] and row["to_node_id"]
        )
        nodes: list[MapNode] = []
        node_ids: set[str] = set()
        root_ids: list[str] = []
        for row in rows:
            node_id = str(row["node_id"])
            node_ids.add(node_id)
            kind = str(row["node_kind"])
            if kind == "root":
                root_ids.append(node_id)
            hostname = str(row["hostname"] or "")
            hop_address = str(row["hop_address"] or "")
            base_label = (
                hostname if kind == "device" and hostname
                else hop_address if kind in {"hop", "unknown_hop"} and hop_address
                else row["node_label"]
            )
            label = sanitize_text(base_label or kind.replace("_", " "), max_chars=120)
            addresses = tuple(
                sanitize_text(item, max_chars=128)
                for item in str(row["addresses"] or "").split(", ")
                if item
            )
            nodes.append(
                MapNode(
                    id=node_id,
                    kind=kind,
                    label=label,
                    addresses=addresses,
                    os_name=sanitize_text(row["os_name"], max_chars=256),
                    open_ports=int(row["open_ports"] or 0),
                    review_count=int(row["review_count"] or 0),
                    distance=0,
                    ports=tuple(
                        sanitize_text(item, max_chars=16)
                        for item in str(row["ports"] or "").split(" ")
                        if item
                    )[:16],
                    member_count=int(row["members"] or 0),
                    assumed=label.startswith("~"),
                    placeholder=kind == "unknown_hop"
                    and str(row["entity_id"] or "").startswith("gateway:"),
                    zone_id=str(row["entity_id"] or "") if kind == "zone" else "",
                    ttl_hops=ttl_hops(row["reason_ttl"]),
                )
            )

        nodes, edges = collapse_duplicates(nodes, edges)
        node_ids = {node.id for node in nodes}

        # The loader never fabricates connectivity; hop distance is BFS over stored edges only.
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
            MapNode(
                n.id,
                n.kind,
                n.label,
                n.addresses,
                n.os_name,
                n.open_ports,
                n.review_count,
                distances.get(n.id, 2 if n.kind != "root" else 0),
                n.ports,
                n.member_count,
                n.assumed,
                n.placeholder,
                n.zone_id,
                n.ttl_hops,
            )
            for n in nodes
        ]
        # The bounded SQL picks nodes by kind and id (index-friendly); order the
        # visible rows for reading here, keeping the scanner root first.
        kind_rank = {"root": 0, "hop": 1, "unknown_hop": 2}
        nodes.sort(key=lambda n: (kind_rank.get(n.kind, 3), n.label.casefold(), n.id))
        scans = conn.execute(
            "SELECT COUNT(*) AS count FROM scans WHERE engagement_id = ?", (engagement_id,)
        ).fetchone()["count"]
        active_scans = conn.execute(
            "SELECT COUNT(*) AS count FROM scans WHERE engagement_id = ? AND status = 'running'",
            (engagement_id,),
        ).fetchone()["count"]
        reviews = conn.execute(
            "SELECT COUNT(*) AS count FROM review_items r WHERE r.engagement_id = ? AND "
            "(SELECT e.state FROM review_events e WHERE e.review_item_id = r.id "
            "ORDER BY e.created_at DESC, e.id DESC LIMIT 1) IN ('unreviewed', 'flagged', 'out_of_scope')",
            (engagement_id,),
        ).fetchone()["count"]
        total_nodes = conn.execute(
            "SELECT COUNT(*) AS count FROM topology_nodes WHERE engagement_id = ?", (engagement_id,)
        ).fetchone()["count"]
        root_row = conn.execute(
            "SELECT tn.label AS node_label, COALESCE(vp.scanner_name, '') AS scanner_name, "
            "tn.entity_id AS vantage_id "
            "FROM topology_nodes tn LEFT JOIN vantage_points vp ON vp.id = tn.entity_id "
            "WHERE tn.engagement_id = ? AND tn.kind = 'root' "
            "ORDER BY tn.created_at, tn.id LIMIT 1",
            (engagement_id,),
        ).fetchone()
        root_label = ""
        root_interfaces: list[str] = []
        if root_row is not None:
            root_label = sanitize_text(
                root_row["scanner_name"] or root_row["node_label"] or "scanner", max_chars=120
            )
            if root_row["vantage_id"]:
                for interface in conn.execute(
                    "SELECT name, address FROM vantage_interfaces "
                    "WHERE vantage_point_id = ? ORDER BY name, address LIMIT 24",
                    (root_row["vantage_id"],),
                ):
                    name = sanitize_text(interface["name"], max_chars=32)
                    address = sanitize_text(interface["address"], max_chars=64)
                    if name and address:
                        root_interfaces.append(f"{name} {address}")
                    elif name or address:
                        root_interfaces.append(name or address)
        scans_detail: list[ScanInfo] = []
        for row in conn.execute(
            "SELECT s.id AS scan_id, s.status AS status, s.targets_json AS targets_json, "
            "s.started_at AS started_at, COALESCE(s.ended_at, '') AS ended_at, "
            "s.exit_code AS exit_code, s.operator AS operator, s.interface AS interface, "
            "s.nmap_version AS nmap_version, "
            "(SELECT COUNT(*) FROM host_observations h WHERE h.scan_id = s.id) AS hosts "
            "FROM scans s WHERE s.engagement_id = ? "
            "ORDER BY s.started_at DESC, s.id DESC LIMIT 25",
            (engagement_id,),
        ):
            try:
                targets = json.loads(row["targets_json"]) if row["targets_json"] else []
            except (TypeError, ValueError):
                targets = []
            if isinstance(targets, dict):
                targets = targets.get("requested") or targets.get("resolved") or []
            if not isinstance(targets, list):
                targets = []
            targets = [str(item) for item in targets]
            scans_detail.append(
                ScanInfo(
                    id=str(row["scan_id"]),
                    status=sanitize_text(row["status"], max_chars=16),
                    targets=tuple(sanitize_text(item, max_chars=64) for item in targets[:8]),
                    started_at=sanitize_text(row["started_at"], max_chars=32),
                    ended_at=sanitize_text(row["ended_at"], max_chars=32),
                    exit_code=row["exit_code"],
                    operator=sanitize_text(row["operator"], max_chars=64),
                    interface=sanitize_text(row["interface"], max_chars=32),
                    nmap_version=sanitize_text(row["nmap_version"], max_chars=64),
                    hosts=int(row["hosts"] or 0),
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
            not_shown=max(0, int(total_nodes) - len(nodes)),
            expanded_zone=expanded_zone,
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
        self._reload = threading.Event()
        self._updates: queue.Queue[MapSnapshot] = queue.Queue(maxsize=1)
        self._error: BaseException | None = None
        self.expanded_zone = ""
        self._thread = threading.Thread(target=self._run, name="lumos-map-watcher", daemon=True)

    @property
    def error(self) -> BaseException | None:
        return self._error

    @property
    def pending(self) -> bool:
        """True while an on-demand reload has not been picked up yet."""
        return self._reload.is_set()

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=6.0)

    def reload_now(self) -> None:
        """Ask the watcher thread for a fresh snapshot without touching the UI."""
        self._reload.set()

    def prime(self, timeout: float = 10.0) -> MapSnapshot | None:
        """Wait for the watcher's first snapshot so the UI never loads one itself."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            latest = self.take_latest()
            if latest is not None:
                return latest
            if self._error is not None:
                return None
            time.sleep(0.02)
        return None

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
            self._publish(load_map_snapshot(self.database, expanded_zone=self.expanded_zone))
            while not self._stop.is_set():
                triggered = self._reload.wait(self.interval)
                if self._stop.is_set():
                    break
                current = int(conn.execute("PRAGMA data_version").fetchone()[0])
                if triggered or current != version:
                    self._reload.clear()
                    version = current
                    self._publish(load_map_snapshot(self.database, expanded_zone=self.expanded_zone))
        except Exception as exc:
            self._error = exc
            self._reload.clear()
        finally:
            if conn is not None:
                conn.close()


def render_plain_snapshot(snapshot: MapSnapshot) -> str:
    """Produce a stable non-interactive fallback without requiring a terminal."""
    lines = [
        f"Lumos - {sanitize_text(snapshot.engagement_name, max_chars=256)}",
        f"Scans: {snapshot.scans} | Active: {snapshot.active_scans} | "
        f"Nodes: {len(snapshot.nodes)} | Review: {snapshot.review_items}"
        + (f" | Not shown: {snapshot.not_shown}" if snapshot.not_shown else ""),
    ]
    for node in snapshot.nodes:
        addresses = ", ".join(node.addresses) if node.addresses else ""
        details = f" [{addresses}]" if addresses else ""
        if node.kind == "device":
            details += f" - {node.open_ports} open ports"
        line = f"{node.kind:12} {node.label}{details}"
        lines.append(sanitize_text(line, max_chars=512))
    if not snapshot.edges:
        lines.append("No topology links recorded.")
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


def load_hub_members(
    database: str | Path, zone_id: str, *, offset: int = 0, limit: int = 50
) -> tuple[tuple[tuple[str, str, str], ...], int]:
    """Page one hub's members without materialising a huge flat network.

    Returns ``((label, address, node_id), ...), total``. A /16 with 60,000
    hosts is one hub; the TUI pages this instead of drawing every member edge.
    Two queries keep it flat: the page of nodes, then one grouped address
    lookup for just those devices.
    """
    if limit < 1:
        raise ValueError("limit must be at least 1")
    conn = open_database(database, readonly=True)
    try:
        total = conn.execute(
            "SELECT COUNT(*) FROM zone_memberships WHERE zone_id = ?", (zone_id,)
        ).fetchone()[0]
        rows = conn.execute(
            "SELECT tn.id AS node_id, tn.label AS label, tn.entity_id AS device_id "
            "FROM zone_memberships zm "
            "JOIN topology_nodes tn ON tn.id = zm.topology_node_id "
            "WHERE zm.zone_id = ? ORDER BY tn.label, tn.id LIMIT ? OFFSET ?",
            (zone_id, int(limit), int(offset)),
        ).fetchall()
        device_ids = [str(row["device_id"]) for row in rows if row["device_id"]]
        addresses: dict[str, str] = {}
        for start in range(0, len(device_ids), 400):
            chunk = device_ids[start:start + 400]
            placeholders = ",".join("?" for _ in chunk)
            for found in conn.execute(
                "SELECT h.device_id AS device_id, group_concat(a.display_value, ', ') AS addresses "
                "FROM host_observations h "
                "JOIN observation_addresses oa ON oa.host_observation_id = h.id "
                "JOIN addresses a ON a.id = oa.address_id "
                f"WHERE h.device_id IN ({placeholders}) GROUP BY h.device_id",
                chunk,
            ):
                addresses[str(found["device_id"])] = str(found["addresses"] or "")
        members = tuple(
            (
                str(row["label"]),
                addresses.get(str(row["device_id"]), ""),
                str(row["node_id"]),
            )
            for row in rows
        )
        return members, int(total)
    finally:
        conn.close()
