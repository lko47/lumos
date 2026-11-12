"""Merge-ready SQLite schema and forward-only migrations for Lumos."""

from __future__ import annotations

APPLICATION_ID = 0x4C554D53  # ASCII "LUMS"; stable for this database format.
SCHEMA_VERSION = 2

# Schema objects are authored here. Import validation will compare against these
# names and column layouts; it must never execute SQL read from an imported file.
_MIGRATION_1 = r"""
CREATE TABLE engagement (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    client TEXT NOT NULL DEFAULT '',
    operator TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE (id)
);

CREATE TABLE networks (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    cidr TEXT,
    family INTEGER CHECK (family IN (4, 6) OR family IS NULL),
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE (engagement_id, name)
);
CREATE INDEX idx_networks_engagement ON networks(engagement_id, name);

CREATE TABLE vantage_points (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    scanner_name TEXT NOT NULL DEFAULT '',
    operator TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX idx_vantage_points_engagement ON vantage_points(engagement_id);

CREATE TABLE vantage_interfaces (
    id TEXT PRIMARY KEY,
    vantage_point_id TEXT NOT NULL REFERENCES vantage_points(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    address TEXT NOT NULL DEFAULT '',
    mac TEXT NOT NULL DEFAULT '',
    is_up INTEGER NOT NULL DEFAULT 0 CHECK (is_up IN (0, 1)),
    captured_at TEXT NOT NULL,
    UNIQUE (vantage_point_id, name, address)
);
CREATE INDEX idx_vantage_interfaces_vantage ON vantage_interfaces(vantage_point_id);

CREATE TABLE devices (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_devices_engagement ON devices(engagement_id, id);

CREATE TABLE addresses (
    id TEXT PRIMARY KEY,
    network_id TEXT NOT NULL REFERENCES networks(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('ipv4', 'ipv6', 'mac')),
    normalized_value TEXT NOT NULL,
    display_value TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (network_id, kind, normalized_value)
);
CREATE INDEX idx_addresses_value ON addresses(kind, normalized_value);
CREATE INDEX idx_addresses_network ON addresses(network_id, kind, normalized_value);

CREATE TABLE identity_claims (
    id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    network_id TEXT REFERENCES networks(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('hostname', 'tls_fingerprint', 'ssh_fingerprint')),
    normalized_value TEXT NOT NULL,
    display_value TEXT NOT NULL DEFAULT '',
    observed_at TEXT NOT NULL,
    source_observation_id TEXT,
    UNIQUE (device_id, kind, normalized_value, source_observation_id)
);
CREATE INDEX idx_identity_claims_match ON identity_claims(network_id, kind, normalized_value);

CREATE TABLE scans (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    vantage_point_id TEXT NOT NULL REFERENCES vantage_points(id),
    exact_args_json TEXT NOT NULL,
    redacted_args_json TEXT NOT NULL,
    targets_json TEXT NOT NULL,
    nmap_version TEXT NOT NULL DEFAULT '',
    interface TEXT NOT NULL DEFAULT '',
    operator TEXT NOT NULL DEFAULT '',
    started_at TEXT NOT NULL,
    ended_at TEXT,
    exit_code INTEGER,
    status TEXT NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'cancelled', 'failed')),
    scope_override INTEGER NOT NULL DEFAULT 0 CHECK (scope_override IN (0, 1)),
    evidence_stored INTEGER NOT NULL DEFAULT 0 CHECK (evidence_stored IN (0, 1))
);
CREATE INDEX idx_scans_engagement_started ON scans(engagement_id, started_at DESC);
CREATE INDEX idx_scans_vantage_started ON scans(vantage_point_id, started_at DESC);

CREATE TABLE host_observations (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    device_id TEXT NOT NULL REFERENCES devices(id),
    observed_at TEXT NOT NULL,
    reachability TEXT NOT NULL DEFAULT 'unknown',
    discovery_method TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    os_name TEXT NOT NULL DEFAULT '',
    os_accuracy INTEGER,
    mac_vendor TEXT NOT NULL DEFAULT '',
    latency_seconds REAL,
    raw_host_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_host_observations_device_time ON host_observations(device_id, observed_at DESC);
CREATE INDEX idx_host_observations_scan ON host_observations(scan_id, observed_at);
CREATE INDEX idx_host_observations_hostname ON host_observations(hostname);

CREATE TABLE observation_addresses (
    host_observation_id TEXT NOT NULL REFERENCES host_observations(id) ON DELETE CASCADE,
    address_id TEXT NOT NULL REFERENCES addresses(id),
    role TEXT NOT NULL DEFAULT 'observed',
    PRIMARY KEY (host_observation_id, address_id, role)
);
CREATE INDEX idx_observation_addresses_address ON observation_addresses(address_id, host_observation_id);

CREATE TABLE port_observations (
    id TEXT PRIMARY KEY,
    host_observation_id TEXT NOT NULL REFERENCES host_observations(id) ON DELETE CASCADE,
    protocol TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port BETWEEN 0 AND 65535),
    state TEXT NOT NULL,
    service TEXT NOT NULL DEFAULT '',
    product TEXT NOT NULL DEFAULT '',
    version TEXT NOT NULL DEFAULT '',
    tunnel TEXT NOT NULL DEFAULT '',
    extra_info TEXT NOT NULL DEFAULT '',
    UNIQUE (host_observation_id, protocol, port)
);
CREATE INDEX idx_port_observations_open ON port_observations(state, protocol, port);
CREATE INDEX idx_port_observations_service ON port_observations(service, port);
CREATE INDEX idx_port_observations_host ON port_observations(host_observation_id, protocol, port);

CREATE TABLE script_observations (
    id TEXT PRIMARY KEY,
    host_observation_id TEXT NOT NULL REFERENCES host_observations(id) ON DELETE CASCADE,
    port_observation_id TEXT REFERENCES port_observations(id) ON DELETE CASCADE,
    script_id TEXT NOT NULL,
    output TEXT NOT NULL DEFAULT '',
    observed_at TEXT NOT NULL
);
CREATE INDEX idx_script_observations_host ON script_observations(host_observation_id, script_id);

CREATE TABLE topology_nodes (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK (kind IN ('root', 'device', 'hop', 'unknown_hop', 'manual', 'zone')),
    entity_id TEXT,
    label TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    UNIQUE (engagement_id, kind, entity_id)
);
CREATE INDEX idx_topology_nodes_engagement_kind ON topology_nodes(engagement_id, kind, id);
CREATE INDEX idx_topology_nodes_entity ON topology_nodes(kind, entity_id);

CREATE TABLE trace_paths (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    vantage_point_id TEXT NOT NULL REFERENCES vantage_points(id),
    root_node_id TEXT REFERENCES topology_nodes(id),
    destination_node_id TEXT REFERENCES topology_nodes(id),
    path_index INTEGER NOT NULL DEFAULT 0,
    observed_at TEXT NOT NULL
);
CREATE INDEX idx_trace_paths_scan ON trace_paths(scan_id, path_index);
CREATE INDEX idx_trace_paths_vantage ON trace_paths(vantage_point_id, observed_at);

CREATE TABLE trace_hops (
    id TEXT PRIMARY KEY,
    trace_path_id TEXT NOT NULL REFERENCES trace_paths(id) ON DELETE CASCADE,
    hop_number INTEGER NOT NULL CHECK (hop_number > 0),
    address_id TEXT REFERENCES addresses(id),
    address_text TEXT NOT NULL DEFAULT '',
    rtt_ms REAL,
    responded INTEGER NOT NULL CHECK (responded IN (0, 1)),
    UNIQUE (trace_path_id, hop_number)
);
CREATE INDEX idx_trace_hops_address ON trace_hops(address_id);

CREATE TABLE manual_nodes (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    node_type TEXT NOT NULL,
    label TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    author TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_manual_nodes_engagement ON manual_nodes(engagement_id, label);

CREATE TABLE zones (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    zone_type TEXT NOT NULL DEFAULT 'subnet',
    description TEXT NOT NULL DEFAULT '',
    author TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_zones_engagement ON zones(engagement_id, name);

CREATE TABLE zone_memberships (
    zone_id TEXT NOT NULL REFERENCES zones(id) ON DELETE CASCADE,
    topology_node_id TEXT NOT NULL REFERENCES topology_nodes(id) ON DELETE CASCADE,
    author TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (zone_id, topology_node_id)
);
CREATE INDEX idx_zone_memberships_node ON zone_memberships(topology_node_id, zone_id);

CREATE TABLE topology_edges (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    from_node_id TEXT NOT NULL REFERENCES topology_nodes(id) ON DELETE CASCADE,
    to_node_id TEXT NOT NULL REFERENCES topology_nodes(id) ON DELETE CASCADE,
    edge_type TEXT NOT NULL CHECK (edge_type IN ('traceroute', 'alternate', 'inferred', 'manual', 'imported')),
    source_kind TEXT NOT NULL,
    source_id TEXT,
    confidence REAL NOT NULL DEFAULT 1.0 CHECK (confidence >= 0.0 AND confidence <= 1.0),
    first_observed_at TEXT NOT NULL,
    last_confirmed_at TEXT,
    author TEXT NOT NULL DEFAULT '',
    CHECK (from_node_id <> to_node_id)
);
CREATE INDEX idx_topology_edges_from ON topology_edges(engagement_id, from_node_id, edge_type);
CREATE INDEX idx_topology_edges_to ON topology_edges(engagement_id, to_node_id, edge_type);
CREATE INDEX idx_topology_edges_source ON topology_edges(source_kind, source_id);

CREATE TABLE node_positions (
    topology_node_id TEXT NOT NULL REFERENCES topology_nodes(id) ON DELETE CASCADE,
    layout_key TEXT NOT NULL DEFAULT 'default',
    x REAL NOT NULL,
    y REAL NOT NULL,
    pinned INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
    grid_x INTEGER NOT NULL DEFAULT 0,
    grid_y INTEGER NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    author TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (topology_node_id, layout_key)
);
CREATE INDEX idx_node_positions_grid ON node_positions(layout_key, grid_x, grid_y, topology_node_id);

CREATE TABLE human_edits (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    object_kind TEXT NOT NULL,
    object_id TEXT NOT NULL,
    field_name TEXT NOT NULL,
    value_json TEXT NOT NULL,
    author TEXT NOT NULL,
    edited_at TEXT NOT NULL,
    client_edit_id TEXT NOT NULL DEFAULT ''
);
CREATE INDEX idx_human_edits_object_field ON human_edits(object_kind, object_id, field_name, edited_at DESC);
CREATE INDEX idx_human_edits_engagement_time ON human_edits(engagement_id, edited_at DESC);

CREATE TABLE notes (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    target_kind TEXT NOT NULL,
    target_id TEXT,
    body_markdown TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE INDEX idx_notes_target ON notes(target_kind, target_id, updated_at DESC);
CREATE INDEX idx_notes_engagement_time ON notes(engagement_id, updated_at DESC);

CREATE TABLE tags (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    normalized_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (engagement_id, normalized_name)
);
CREATE INDEX idx_tags_name ON tags(engagement_id, normalized_name);

CREATE TABLE tag_links (
    tag_id TEXT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    object_kind TEXT NOT NULL,
    object_id TEXT NOT NULL,
    author TEXT NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (tag_id, object_kind, object_id)
);
CREATE INDEX idx_tag_links_object ON tag_links(object_kind, object_id, tag_id);

CREATE TABLE review_items (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    target_kind TEXT NOT NULL,
    target_id TEXT NOT NULL,
    reason_code TEXT NOT NULL,
    reason_detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL,
    latest_event_at TEXT NOT NULL
);
CREATE INDEX idx_review_items_recency ON review_items(engagement_id, latest_event_at DESC);
CREATE INDEX idx_review_items_target ON review_items(target_kind, target_id, reason_code);

CREATE TABLE review_events (
    id TEXT PRIMARY KEY,
    review_item_id TEXT NOT NULL REFERENCES review_items(id) ON DELETE CASCADE,
    state TEXT NOT NULL CHECK (state IN ('unreviewed', 'confirmed', 'ignored', 'flagged', 'out_of_scope')),
    reason_detail TEXT NOT NULL DEFAULT '',
    author TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_review_events_item_time ON review_events(review_item_id, created_at DESC);
CREATE INDEX idx_review_events_state_time ON review_events(state, created_at DESC);

CREATE TABLE duplicate_proposals (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    left_kind TEXT NOT NULL,
    left_id TEXT NOT NULL,
    right_kind TEXT NOT NULL,
    right_id TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    CHECK (left_kind <> right_kind OR left_id <> right_id)
);
CREATE INDEX idx_duplicate_proposals_pair ON duplicate_proposals(left_kind, left_id, right_kind, right_id);
CREATE INDEX idx_duplicate_proposals_engagement ON duplicate_proposals(engagement_id, created_at DESC);

CREATE TABLE duplicate_proposal_events (
    id TEXT PRIMARY KEY,
    proposal_id TEXT NOT NULL REFERENCES duplicate_proposals(id) ON DELETE CASCADE,
    decision TEXT NOT NULL CHECK (decision IN ('accepted_link', 'rejected')),
    author TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_duplicate_proposal_events_proposal ON duplicate_proposal_events(proposal_id, created_at DESC);

CREATE TABLE scope_rules (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    rule_kind TEXT NOT NULL CHECK (rule_kind IN ('cidr', 'range', 'hostname', 'target_file')),
    rule_value TEXT NOT NULL,
    included INTEGER NOT NULL CHECK (included IN (0, 1)),
    author TEXT NOT NULL,
    created_at TEXT NOT NULL
);
CREATE INDEX idx_scope_rules_engagement ON scope_rules(engagement_id, included, rule_kind);

CREATE TABLE audit_events (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagement(id) ON DELETE CASCADE,
    scan_id TEXT REFERENCES scans(id),
    event_type TEXT NOT NULL,
    argv_json TEXT NOT NULL DEFAULT '[]',
    targets_json TEXT NOT NULL DEFAULT '[]',
    operator TEXT NOT NULL DEFAULT '',
    occurred_at TEXT NOT NULL,
    exit_code INTEGER,
    scope_override INTEGER NOT NULL DEFAULT 0 CHECK (scope_override IN (0, 1)),
    details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_audit_events_time ON audit_events(engagement_id, occurred_at DESC);
CREATE INDEX idx_audit_events_scan ON audit_events(scan_id, occurred_at);

CREATE TABLE raw_scan_evidence (
    scan_id TEXT PRIMARY KEY REFERENCES scans(id) ON DELETE CASCADE,
    compression TEXT NOT NULL CHECK (compression IN ('gzip', 'none')),
    byte_length INTEGER NOT NULL CHECK (byte_length >= 0),
    payload BLOB NOT NULL,
    sha256 TEXT NOT NULL,
    stored_at TEXT NOT NULL
);

CREATE VIEW v_device_seen AS
SELECT d.id AS device_id,
       MIN(h.observed_at) AS first_seen,
       MAX(h.observed_at) AS last_seen
FROM devices AS d
LEFT JOIN host_observations AS h ON h.device_id = d.id
GROUP BY d.id;

CREATE VIEW v_current_host_observations AS
SELECT h.*
FROM host_observations AS h
WHERE h.observed_at = (
    SELECT MAX(h2.observed_at)
    FROM host_observations AS h2
    WHERE h2.device_id = h.device_id
);
"""

MIGRATIONS = {1: _MIGRATION_1}

# Schema 2 makes the file mergeable: deterministic natural-key indexes, an
# engagement identity record, and a log of merge attempts. Exact duplicate rows
# are collapsed to the earliest row before each unique index is created, so a
# pre-existing engagement file can be upgraded in place.
_MIGRATION_2 = r"""
CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE merge_log (
    id TEXT PRIMARY KEY,
    applied_at TEXT NOT NULL,
    source_label TEXT NOT NULL DEFAULT '',
    source_application_id INTEGER NOT NULL,
    source_user_version INTEGER NOT NULL,
    source_engagement_uid TEXT NOT NULL DEFAULT '',
    dry_run INTEGER NOT NULL DEFAULT 0 CHECK (dry_run IN (0, 1)),
    operator TEXT NOT NULL DEFAULT '',
    outcome TEXT NOT NULL CHECK (outcome IN ('applied', 'rejected', 'dry_run')),
    stats_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_merge_log_applied ON merge_log(applied_at DESC);

DELETE FROM scope_rules WHERE rowid NOT IN (
    SELECT MIN(rowid) FROM scope_rules
    GROUP BY engagement_id, rule_kind, rule_value, included);
CREATE UNIQUE INDEX ux_scope_rules_natural
    ON scope_rules(engagement_id, rule_kind, rule_value, included);

DELETE FROM review_items WHERE rowid NOT IN (
    SELECT MIN(rowid) FROM review_items
    GROUP BY engagement_id, target_kind, target_id, reason_code);
CREATE UNIQUE INDEX ux_review_items_natural
    ON review_items(engagement_id, target_kind, target_id, reason_code);

DELETE FROM duplicate_proposals WHERE rowid NOT IN (
    SELECT MIN(rowid) FROM duplicate_proposals
    GROUP BY left_kind, left_id, right_kind, right_id);
CREATE UNIQUE INDEX ux_duplicate_proposals_natural
    ON duplicate_proposals(left_kind, left_id, right_kind, right_id);

DELETE FROM topology_edges WHERE rowid NOT IN (
    SELECT MIN(rowid) FROM topology_edges
    GROUP BY engagement_id, from_node_id, to_node_id, edge_type, source_kind);
CREATE UNIQUE INDEX ux_topology_edges_natural
    ON topology_edges(engagement_id, from_node_id, to_node_id, edge_type, source_kind);

DELETE FROM vantage_points WHERE rowid NOT IN (
    SELECT MIN(rowid) FROM vantage_points
    GROUP BY engagement_id, scanner_name);
CREATE UNIQUE INDEX ux_vantage_points_scanner
    ON vantage_points(engagement_id, scanner_name);

DELETE FROM trace_paths WHERE rowid NOT IN (
    SELECT MIN(rowid) FROM trace_paths
    GROUP BY scan_id, IFNULL(destination_node_id, ''), path_index);
CREATE UNIQUE INDEX ux_trace_paths_destination
    ON trace_paths(scan_id, IFNULL(destination_node_id, ''), path_index);

DELETE FROM script_observations WHERE rowid NOT IN (
    SELECT MIN(rowid) FROM script_observations
    GROUP BY host_observation_id, IFNULL(port_observation_id, ''), script_id);
CREATE UNIQUE INDEX ux_script_observations_natural
    ON script_observations(host_observation_id, IFNULL(port_observation_id, ''), script_id);

DELETE FROM identity_claims WHERE rowid NOT IN (
    SELECT MIN(rowid) FROM identity_claims
    GROUP BY device_id, kind, normalized_value, IFNULL(source_observation_id, ''));
CREATE UNIQUE INDEX ux_identity_claims_natural
    ON identity_claims(device_id, kind, normalized_value, IFNULL(source_observation_id, ''));
"""

MIGRATIONS[2] = _MIGRATION_2

# The application id is written from the constant so the file identity and the
# validator can never drift apart.
_MIGRATION_1 = "PRAGMA application_id = %d;\n" % APPLICATION_ID + _MIGRATION_1
MIGRATIONS[1] = _MIGRATION_1
