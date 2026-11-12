"""Merge another copy of the same engagement into this database.

Identity is what makes this safe: every row id is derived from natural keys,
so merging the same source twice adds nothing, and a source that belongs to a
different engagement (different ``meta.engagement_uid``) is rejected and
recorded rather than silently rehomed.
"""

from __future__ import annotations

import json
import sqlite3
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from . import ids
from .database import DatabaseError, open_database, utc_now
from .inference import rebuild_inferred
from .text import sanitize_text

# Parents before children, so foreign keys hold at every step.
TABLES: tuple[str, ...] = (
    "networks",
    "vantage_points",
    "vantage_interfaces",
    "vantage_routes",
    "devices",
    "addresses",
    "observation_addresses",
    "scans",
    "host_observations",
    "port_observations",
    "script_observations",
    "topology_nodes",
    "topology_edges",
    "trace_paths",
    "trace_hops",
    "manual_nodes",
    "zones",
    "zone_memberships",
    "node_positions",
    "human_edits",
    "notes",
    "tags",
    "tag_links",
    "review_items",
    "review_events",
    "duplicate_proposals",
    "duplicate_proposal_events",
    "scope_rules",
    "audit_events",
    "raw_scan_evidence",
    "edge_decisions",
)

CHUNK = 2000


class MergeError(DatabaseError):
    """The source database cannot be merged into the target."""


@dataclass(frozen=True)
class MergeStats:
    applied: bool
    dry_run: bool
    outcome: str
    reason: str = ""
    source_engagement_uid: str = ""
    rows: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.rows.values())


def _columns(conn: sqlite3.Connection, schema: str, table: str) -> list[str]:
    rows = conn.execute(f"PRAGMA {schema}.table_info({table})").fetchall()
    return [str(row[1]) for row in rows]


def _count(conn: sqlite3.Connection, table: str, engagement_id: str) -> int:
    columns = _columns(conn, "main", table)
    if "engagement_id" in columns:
        return int(
            conn.execute(f"SELECT COUNT(*) FROM {table} WHERE engagement_id = ?", (engagement_id,)).fetchone()[0]
        )
    return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def _log(
    conn: sqlite3.Connection,
    *,
    engagement_id: str,
    source_label: str,
    source_application_id: int | None,
    source_user_version: int | None,
    source_uid: str,
    dry_run: bool,
    operator: str,
    outcome: str,
    stats: dict[str, int],
    reason: str = "",
) -> None:
    conn.execute(
        "INSERT INTO merge_log(id, applied_at, source_label, source_application_id, source_user_version, "
        "source_engagement_uid, dry_run, operator, outcome, stats_json) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            uuid.uuid4().hex,
            utc_now(),
            sanitize_text(source_label, max_chars=512),
            int(source_application_id or 0),
            int(source_user_version or 0),
            source_uid,
            int(dry_run),
            sanitize_text(operator, max_chars=256),
            outcome,
            json.dumps({"rows": stats, "reason": reason}, sort_keys=True),
        ),
    )


def _copy_rows(
    target: sqlite3.Connection,
    source: sqlite3.Connection,
    engagement_id: str,
    source_tables: set[str],
) -> dict[str, int]:
    """Insert every row of the source, ignoring ones that already exist.

    Returns the number of rows actually inserted per table, so a dry run and a
    real merge report the same thing.
    """
    rows: dict[str, int] = {}
    for table in TABLES:
        if table not in source_tables:
            continue
        source_columns = _columns(source, "main", table)
        target_columns = set(_columns(target, "main", table))
        columns = [column for column in source_columns if column in target_columns]
        if not columns:
            continue
        placeholders = ",".join("?" for _ in columns)
        statement = f"INSERT OR IGNORE INTO {table}({','.join(columns)}) VALUES ({placeholders})"
        renamed = "engagement_id" in columns
        cursor = source.execute(f"SELECT {','.join(columns)} FROM {table}")
        inserted = 0
        while True:
            batch = cursor.fetchmany(CHUNK)
            if not batch:
                break
            payload = [
                tuple(
                    engagement_id if (renamed and column == "engagement_id") else row[column]
                    for column in columns
                )
                for row in batch
            ]
            before = target.total_changes
            target.executemany(statement, payload)
            inserted += target.total_changes - before
        rows[table] = inserted
    return rows


def merge_engagement(
    target_path: str | Path,
    source_path: str | Path,
    *,
    operator: str = "",
    dry_run: bool = False,
) -> MergeStats:
    """Copy every row of ``source_path`` into ``target_path`` when the uids match."""
    target_file = Path(target_path).expanduser().absolute()
    source_file = Path(source_path).expanduser().absolute()
    if target_file == source_file:
        raise MergeError("Refusing to merge a database into itself")
    if not source_file.is_file():
        raise MergeError(f"Source database does not exist: {source_file}")

    target = open_database(target_file, readonly=False)
    try:
        source = sqlite3.connect(f"file:{source_file}?mode=ro", uri=True)
        source.row_factory = sqlite3.Row
        try:
            engagement = target.execute("SELECT id FROM engagement LIMIT 1").fetchone()
            if engagement is None:
                raise MergeError("Target database has no engagement")
            engagement_id = str(engagement[0])
            target_uid = ids.ensure_engagement_uid(target)
            source_app_id = int(source.execute("PRAGMA application_id").fetchone()[0])
            source_version = int(source.execute("PRAGMA user_version").fetchone()[0])
            try:
                source_uid = ids.read_engagement_uid(source)
            except (ValueError, sqlite3.Error) as exc:
                raise MergeError(f"Source is not a Lumos engagement: {sanitize_text(exc, max_chars=512)}") from exc
            if source_uid != target_uid:
                reason = (
                    "Source belongs to a different engagement "
                    f"({source_uid[:8]}… != {target_uid[:8]}…); refusing to merge."
                )
                if not dry_run:
                    with target:
                        _log(
                            target,
                            engagement_id=engagement_id,
                            source_label=str(source_file),
                            source_application_id=source_app_id,
                            source_user_version=source_version,
                            source_uid=source_uid,
                            dry_run=False,
                            operator=operator,
                            outcome="rejected",
                            stats={},
                            reason=reason,
                        )
                raise MergeError(reason)

            source_tables = {
                str(row[0])
                for row in source.execute("SELECT name FROM sqlite_master WHERE type = 'table'").fetchall()
            }
            rows: dict[str, int] = {}
            if dry_run:
                target.execute("SAVEPOINT dry_run")
                try:
                    rows = _copy_rows(target, source, engagement_id, source_tables)
                finally:
                    target.execute("ROLLBACK TO dry_run")
                    target.execute("RELEASE dry_run")
                with target:
                    _log(
                        target,
                        engagement_id=engagement_id,
                        source_label=str(source_file),
                        source_application_id=source_app_id,
                        source_user_version=source_version,
                        source_uid=source_uid,
                        dry_run=True,
                        operator=operator,
                        outcome="dry_run",
                        stats=rows,
                        reason="dry run: nothing was copied",
                    )
                return MergeStats(
                    applied=False,
                    dry_run=True,
                    outcome="dry_run",
                    reason="dry run: nothing was copied",
                    source_engagement_uid=source_uid,
                    rows=rows,
                )

            with target:
                rows = _copy_rows(target, source, engagement_id, source_tables)
                _log(
                    target,
                    engagement_id=engagement_id,
                    source_label=str(source_file),
                    source_application_id=source_app_id,
                    source_user_version=source_version,
                    source_uid=source_uid,
                    dry_run=False,
                    operator=operator,
                    outcome="applied",
                    stats=rows,
                )
            rebuild_inferred(target_file)
            return MergeStats(
                applied=True,
                dry_run=False,
                outcome="applied",
                source_engagement_uid=source_uid,
                rows=rows,
            )
        finally:
            source.close()
    finally:
        target.close()
