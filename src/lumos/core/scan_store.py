"""Single-writer scan persistence for scan and XML import workflows."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import queue
import re
import threading
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .database import DatabaseError, open_database, utc_now
from .nmap.xml_stream import AddressRecord, HostRecord, NmapXmlError
from .scope import ScopeRule, is_target_in_scope
from .text import sanitize_text

_BATCH_SIZE = 50
_MAC = re.compile(r"^[0-9a-fA-F]{12}$")


class ScanStoreError(RuntimeError):
    """Could not write a scan result to the engagement database."""


def _normalized_address(address: AddressRecord) -> tuple[str, str] | None:
    value = address.value.strip()
    if address.kind in {"ipv4", "ipv6"}:
        try:
            parsed = ipaddress.ip_address(value)
        except ValueError:
            return None
        if parsed.version != (4 if address.kind == "ipv4" else 6):
            return None
        return address.kind, parsed.compressed.lower()
    if address.kind == "mac":
        compact = re.sub(r"[^0-9a-fA-F]", "", value)
        if not _MAC.fullmatch(compact):
            return None
        display = ":".join(compact[i : i + 2].lower() for i in range(0, 12, 2))
        return "mac", display
    return None


def _insert_review(
    conn,
    engagement_id: str,
    target_kind: str,
    target_id: str,
    reason_code: str,
    detail: str,
    *,
    state: str = "unreviewed",
) -> None:
    now = utc_now()
    existing = conn.execute(
        "SELECT id FROM review_items WHERE engagement_id = ? AND target_kind = ? "
        "AND target_id = ? AND reason_code = ?",
        (engagement_id, target_kind, target_id, reason_code),
    ).fetchone()
    if existing:
        item_id = existing[0]
        conn.execute("UPDATE review_items SET latest_event_at = ? WHERE id = ?", (now, item_id))
    else:
        item_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO review_items(id, engagement_id, target_kind, target_id, reason_code, reason_detail, created_at, latest_event_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (item_id, engagement_id, target_kind, target_id, reason_code, sanitize_text(detail), now, now),
        )
    conn.execute(
        "INSERT INTO review_events(id, review_item_id, state, reason_detail, author, created_at) "
        "VALUES (?, ?, ?, ?, 'system', ?)",
        (str(uuid.uuid4()), item_id, state, sanitize_text(detail), now),
    )


def _ensure_address(conn, network_id: str, address: AddressRecord, created_at: str) -> str | None:
    normalized = _normalized_address(address)
    if normalized is None:
        return None
    kind, value = normalized
    conn.execute(
        "INSERT INTO addresses(id, network_id, kind, normalized_value, display_value, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(network_id, kind, normalized_value) DO NOTHING",
        (str(uuid.uuid4()), network_id, kind, value, sanitize_text(address.value, max_chars=256), created_at),
    )
    row = conn.execute(
        "SELECT id FROM addresses WHERE network_id = ? AND kind = ? AND normalized_value = ?",
        (network_id, kind, value),
    ).fetchone()
    return row[0] if row else None


def _add_duplicate_proposal(
    conn,
    engagement_id: str,
    left_device: str,
    right_device: str,
    evidence: dict[str, Any],
    created_at: str,
) -> None:
    if left_device == right_device:
        return
    left, right = sorted((left_device, right_device))
    existing = conn.execute(
        "SELECT id FROM duplicate_proposals WHERE left_kind = 'device' AND left_id = ? "
        "AND right_kind = 'device' AND right_id = ?",
        (left, right),
    ).fetchone()
    if existing:
        return
    proposal_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO duplicate_proposals(id, engagement_id, left_kind, left_id, right_kind, right_id, evidence_json, created_at) "
        "VALUES (?, ?, 'device', ?, 'device', ?, ?, ?)",
        (proposal_id, engagement_id, left, right, json.dumps(evidence, ensure_ascii=False, sort_keys=True), created_at),
    )
    _insert_review(
        conn,
        engagement_id,
        "duplicate_proposal",
        proposal_id,
        "possible_duplicate",
        "Possible duplicate device; no automatic merge was performed.",
    )


def _persist_host(conn, context: dict[str, Any], host: HostRecord) -> None:
    now = utc_now()
    engagement_id = context["engagement_id"]
    network_id = context["network_id"]
    scan_id = context["scan_id"]
    device_id = str(uuid.uuid4())
    observation_id = str(uuid.uuid4())
    conn.execute(
        "INSERT INTO devices(id, engagement_id, created_at) VALUES (?, ?, ?)",
        (device_id, engagement_id, now),
    )
    mac_vendor = next((a.vendor for a in host.addresses if a.kind == "mac" and a.vendor), "")
    host_json = json.dumps(asdict(host), ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    conn.execute(
        "INSERT INTO host_observations(id, scan_id, device_id, observed_at, reachability, discovery_method, hostname, os_name, os_accuracy, mac_vendor, latency_seconds, raw_host_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            observation_id,
            scan_id,
            device_id,
            now,
            sanitize_text(host.state, max_chars=64),
            sanitize_text(host.reason, max_chars=256),
            sanitize_text(host.hostnames[0] if host.hostnames else "", max_chars=1024),
            sanitize_text(host.os_name, max_chars=1024),
            host.os_accuracy,
            sanitize_text(mac_vendor, max_chars=512),
            host.latency_seconds,
            host_json,
        ),
    )

    normalized_observed: list[tuple[str, str, str]] = []
    out_of_scope_values: list[str] = []
    address_ids: list[tuple[str, AddressRecord]] = []
    for address in host.addresses:
        address_id = _ensure_address(conn, network_id, address, now)
        normalized = _normalized_address(address)
        if not address_id or not normalized:
            continue
        kind, value = normalized
        conn.execute(
            "INSERT OR IGNORE INTO observation_addresses(host_observation_id, address_id, role) VALUES (?, ?, ?)",
            (observation_id, address_id, kind),
        )
        normalized_observed.append((address_id, kind, value))
        address_ids.append((address_id, address))
        if kind in {"ipv4", "ipv6"}:
            decision = is_target_in_scope(value, context["scope_rules"])
            if not decision.allowed:
                out_of_scope_values.append(value)
        # The address is a match candidate only. Keep both device records and queue a proposal.
        previous = conn.execute(
            "SELECT DISTINCT h.device_id FROM observation_addresses oa "
            "JOIN host_observations h ON h.id = oa.host_observation_id "
            "WHERE oa.address_id = ? AND h.device_id <> ?",
            (address_id, device_id),
        ).fetchall()
        for row in previous:
            _add_duplicate_proposal(
                conn,
                engagement_id,
                device_id,
                row[0],
                {"network_address": value, "address_kind": kind, "rule": "candidate only; never auto-merge by address"},
                now,
            )

    for hostname in host.hostnames:
        norm = sanitize_text(hostname, max_chars=1024).strip().lower()
        if not norm:
            continue
        old = conn.execute(
            "SELECT DISTINCT device_id FROM identity_claims WHERE network_id = ? AND kind = 'hostname' "
            "AND normalized_value = ? AND device_id <> ?",
            (network_id, norm, device_id),
        ).fetchall()
        for row in old:
            _add_duplicate_proposal(
                conn,
                engagement_id,
                device_id,
                row[0],
                {"hostname": norm, "rule": "candidate only; review required"},
                now,
            )
        conn.execute(
            "INSERT INTO identity_claims(id, device_id, network_id, kind, normalized_value, display_value, observed_at, source_observation_id) "
            "VALUES (?, ?, ?, 'hostname', ?, ?, ?, ?)",
            (str(uuid.uuid4()), device_id, network_id, norm, sanitize_text(hostname), now, observation_id),
        )

    port_ids: dict[int, str] = {}
    for port in host.ports:
        port_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO port_observations(id, host_observation_id, protocol, port, state, service, product, version, tunnel, extra_info) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                port_id,
                observation_id,
                sanitize_text(port.protocol, max_chars=32),
                port.port,
                sanitize_text(port.state, max_chars=64),
                sanitize_text(port.service, max_chars=512),
                sanitize_text(port.product, max_chars=512),
                sanitize_text(port.version, max_chars=512),
                sanitize_text(port.tunnel, max_chars=128),
                sanitize_text(port.extra_info, max_chars=1024),
            ),
        )
        port_ids[port.port] = port_id
    for script in host.scripts:
        conn.execute(
            "INSERT INTO script_observations(id, host_observation_id, port_observation_id, script_id, output, observed_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                observation_id,
                port_ids.get(script.port) if script.port is not None else None,
                sanitize_text(script.script_id, max_chars=256),
                sanitize_text(script.output),
                now,
            ),
        )

    node_id = str(uuid.uuid4())
    primary = next((a.value for a in host.addresses if a.kind in {"ipv4", "ipv6"}), "")
    label = host.hostnames[0] if host.hostnames else primary or f"device-{device_id[:8]}"
    conn.execute(
        "INSERT INTO topology_nodes(id, engagement_id, kind, entity_id, label, created_at) VALUES (?, ?, 'device', ?, ?, ?)",
        (node_id, engagement_id, device_id, sanitize_text(label, max_chars=512), now),
    )

    if not host.hostnames:
        _insert_review(conn, engagement_id, "host_observation", observation_id, "no_hostname", "No hostname was reported by Nmap.")
    if not host.os_name or host.os_accuracy is None or host.os_accuracy < 80:
        _insert_review(conn, engagement_id, "host_observation", observation_id, "no_reliable_os", "No reliable OS match was reported by Nmap.")
    if any(a.kind == "mac" for a in host.addresses) and not mac_vendor:
        _insert_review(conn, engagement_id, "host_observation", observation_id, "unknown_mac_vendor", "Nmap did not identify a MAC vendor.")
    if not host.ports:
        _insert_review(conn, engagement_id, "host_observation", observation_id, "no_port_data", "Host was seen without port data (for example ARP or ping discovery).")
    for port in host.ports:
        if port.state == "open" and (not port.service or port.service.lower() in {"unknown", "tcpwrapped"}):
            _insert_review(
                conn,
                engagement_id,
                "port_observation",
                port_ids[port.port],
                "unknown_open_service",
                f"Open {port.protocol}/{port.port} has service {port.service or 'unknown'}.",
            )
    if out_of_scope_values:
        _insert_review(
            conn,
            engagement_id,
            "host_observation",
            observation_id,
            "discovered_out_of_scope",
            "Nmap returned address(es) outside configured scope: " + ", ".join(sorted(set(out_of_scope_values))),
            state="out_of_scope",
        )

    if host.hops:
        path_id = str(uuid.uuid4())
        root_id = context["root_node_id"]
        conn.execute(
            "INSERT INTO trace_paths(id, scan_id, vantage_point_id, root_node_id, destination_node_id, path_index, observed_at) "
            "VALUES (?, ?, ?, ?, ?, 0, ?)",
            (path_id, scan_id, context["vantage_id"], root_id, node_id, now),
        )
        path_nodes = [root_id]
        for hop in host.hops:
            trace_hop_id = str(uuid.uuid4())
            address_id = None
            if hop.responded and hop.address:
                kind = "ipv6" if ":" in hop.address else "ipv4"
                address_id = _ensure_address(conn, network_id, AddressRecord(kind, hop.address), now)
            conn.execute(
                "INSERT INTO trace_hops(id, trace_path_id, hop_number, address_id, address_text, rtt_ms, responded) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (trace_hop_id, path_id, hop.ttl, address_id, hop.address, hop.rtt_ms, int(hop.responded)),
            )
            hop_node_id = str(uuid.uuid4())
            hop_kind = "hop" if hop.responded else "unknown_hop"
            hop_label = hop.hostname or hop.address or f"unresponsive hop {hop.ttl}"
            conn.execute(
                "INSERT INTO topology_nodes(id, engagement_id, kind, entity_id, label, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (hop_node_id, engagement_id, hop_kind, trace_hop_id, sanitize_text(hop_label, max_chars=512), now),
            )
            path_nodes.append(hop_node_id)
            if not hop.responded:
                _insert_review(conn, engagement_id, "topology_node", hop_node_id, "unresponsive_traceroute_hop", f"Traceroute hop {hop.ttl} did not reply.")
            elif hop.address and not is_target_in_scope(hop.address, context["scope_rules"]).allowed:
                _insert_review(
                    conn,
                    engagement_id,
                    "topology_node",
                    hop_node_id,
                    "discovered_out_of_scope",
                    f"Traceroute hop address {hop.address} is outside configured scope.",
                    state="out_of_scope",
                )
        path_nodes.append(node_id)
        for left, right in zip(path_nodes, path_nodes[1:]):
            if left == right:
                continue
            conn.execute(
                "INSERT INTO topology_edges(id, engagement_id, from_node_id, to_node_id, edge_type, source_kind, source_id, confidence, first_observed_at) "
                "VALUES (?, ?, ?, ?, 'traceroute', 'nmap_xml', ?, 1.0, ?)",
                (str(uuid.uuid4()), engagement_id, left, right, path_id, now),
            )


class ScanWriter:
    """A single dedicated thread owns all database writes for one scan."""

    def __init__(self, database_path: str | Path, context: dict[str, Any], *, batch_size: int = _BATCH_SIZE):
        self.database_path = Path(database_path)
        self.context = context
        self.batch_size = max(1, batch_size)
        self._queue: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=128)
        self._ready: queue.Queue[BaseException | None] = queue.Queue(maxsize=1)
        self._error: BaseException | None = None
        self._thread = threading.Thread(target=self._run, name="lumos-db-writer", daemon=True)
        self._thread.start()
        self._queue.put(("start", None))
        startup_error = self._ready.get()
        if startup_error is not None:
            raise ScanStoreError(f"Could not initialize scan storage: {startup_error}") from startup_error

    def submit_host(self, host: HostRecord) -> None:
        if self._error is not None:
            raise ScanStoreError(f"Database writer failed: {self._error}") from self._error
        self._queue.put(("host", host))

    def finish(
        self,
        *,
        exit_code: int,
        status: str,
        evidence: bytes | None,
        evidence_bytes: int,
        evidence_sha256: str,
        detail: str = "",
    ) -> None:
        self._queue.put(
            ("finish", (exit_code, status, evidence, evidence_bytes, evidence_sha256, sanitize_text(detail, max_chars=4096)))
        )
        self._thread.join()
        if self._error is not None:
            raise ScanStoreError(f"Database writer failed: {self._error}") from self._error

    def _run(self) -> None:
        conn = None
        batch: list[HostRecord] = []
        active = False
        try:
            conn = open_database(self.database_path)
            message, _ = self._queue.get()
            if message != "start":
                raise ScanStoreError("Scan writer did not receive start message")
            self._initialize(conn)
            conn.commit()
            active = True
            self._ready.put(None)
            while True:
                message, payload = self._queue.get()
                if message == "host":
                    if self._error is None:
                        batch.append(payload)
                        if len(batch) >= self.batch_size:
                            self._flush(conn, batch)
                    continue
                if message == "finish":
                    if self._error is None:
                        if batch:
                            self._flush(conn, batch)
                        self._finalize(conn, payload)
                        conn.commit()
                    break
        except BaseException as exc:
            self._error = exc
            if not active:
                try:
                    self._ready.put_nowait(exc)
                except queue.Full:
                    pass
        finally:
            if conn is not None:
                try:
                    if conn.in_transaction:
                        conn.rollback()
                finally:
                    conn.close()

    def _initialize(self, conn) -> None:
        ctx = self.context
        engagement_id = ctx["engagement_id"]
        vantage = conn.execute(
            "SELECT id FROM vantage_points WHERE engagement_id = ? AND scanner_name = ?",
            (engagement_id, ctx["scanner_name"]),
        ).fetchone()
        if vantage:
            vantage_id = vantage[0]
        else:
            vantage_id = str(uuid.uuid4())
            conn.execute(
                "INSERT INTO vantage_points(id, engagement_id, scanner_name, operator, created_at) VALUES (?, ?, ?, ?, ?)",
                (vantage_id, engagement_id, ctx["scanner_name"], ctx["operator"], ctx["started_at"]),
            )
        root = conn.execute(
            "SELECT id FROM topology_nodes WHERE engagement_id = ? AND kind = 'root' AND entity_id = ?",
            (engagement_id, vantage_id),
        ).fetchone()
        root_id = root[0] if root else str(uuid.uuid4())
        if not root:
            conn.execute(
                "INSERT INTO topology_nodes(id, engagement_id, kind, entity_id, label, created_at) VALUES (?, ?, 'root', ?, ?, ?)",
                (root_id, engagement_id, vantage_id, ctx["scanner_name"], ctx["started_at"]),
            )
        ctx["vantage_id"] = vantage_id
        ctx["root_node_id"] = root_id
        conn.execute(
            "INSERT INTO scans(id, engagement_id, vantage_point_id, exact_args_json, redacted_args_json, targets_json, nmap_version, interface, operator, started_at, status, scope_override, evidence_stored) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'running', ?, ?)",
            (
                ctx["scan_id"], engagement_id, vantage_id, ctx["args_json"], ctx["args_json"], ctx["targets_json"],
                ctx["nmap_version"], ctx["interface"], ctx["operator"], ctx["started_at"],
                int(ctx["scope_override"]), int(ctx["evidence_enabled"]),
            ),
        )
        conn.execute(
            "INSERT INTO audit_events(id, engagement_id, scan_id, event_type, argv_json, targets_json, operator, occurred_at, scope_override, details_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, '{}')",
            (
                str(uuid.uuid4()), engagement_id, ctx["scan_id"], ctx.get("event_started", "scan_started"),
                ctx["args_json"], ctx["targets_json"], ctx["operator"], ctx["started_at"], int(ctx["scope_override"]),
            ),
        )

    def _flush(self, conn, hosts: list[HostRecord]) -> None:
        try:
            with conn:
                for host in hosts:
                    _persist_host(conn, self.context, host)
            hosts.clear()
        except BaseException as exc:
            self._error = exc
            hosts.clear()
            if conn.in_transaction:
                conn.rollback()

    def _finalize(self, conn, data: tuple[Any, ...]) -> None:
        exit_code, status, evidence, evidence_bytes, evidence_sha256, detail = data
        now = utc_now()
        conn.execute(
            "UPDATE scans SET ended_at = ?, exit_code = ?, status = ? WHERE id = ?",
            (now, exit_code, status, self.context["scan_id"]),
        )
        conn.execute(
            "INSERT INTO audit_events(id, engagement_id, scan_id, event_type, argv_json, targets_json, operator, occurred_at, exit_code, scope_override, details_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                str(uuid.uuid4()), self.context["engagement_id"], self.context["scan_id"],
                self.context.get("event_finished", "scan_finished"), self.context["args_json"],
                self.context["targets_json"], self.context["operator"], now, exit_code,
                int(self.context["scope_override"]), json.dumps({"status": status, "detail": detail}, ensure_ascii=False),
            ),
        )
        if evidence is not None:
            conn.execute(
                "INSERT INTO raw_scan_evidence(scan_id, compression, byte_length, payload, sha256, stored_at) VALUES (?, 'gzip', ?, ?, ?, ?)",
                (self.context["scan_id"], evidence_bytes, evidence, evidence_sha256, now),
            )


def make_scan_context(
    *,
    engagement_id: str,
    network_id: str,
    targets: list[str],
    resolved_targets: list[str],
    argv: list[str],
    nmap_version: str,
    scanner_name: str,
    operator: str,
    interface: str,
    scope_override: bool,
    evidence_enabled: bool,
) -> dict[str, Any]:
    from .nmap.runner import redacted_argv

    return {
        "scan_id": str(uuid.uuid4()),
        "engagement_id": engagement_id,
        "network_id": network_id,
        "scope_rules": [],
        "args_json": json.dumps(redacted_argv(argv), ensure_ascii=False),
        "targets_json": json.dumps({"requested": targets, "resolved": resolved_targets}, ensure_ascii=False),
        "nmap_version": sanitize_text(nmap_version, max_chars=256),
        "scanner_name": sanitize_text(scanner_name, max_chars=512),
        "operator": sanitize_text(operator, max_chars=256),
        "interface": sanitize_text(interface, max_chars=256),
        "started_at": utc_now(),
        "scope_override": scope_override,
        "evidence_enabled": evidence_enabled,
        "event_started": "scan_started",
        "event_finished": "scan_finished",
    }
