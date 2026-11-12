"""SQLite connection setup, secure database creation, and schema migrations."""

from __future__ import annotations

import os
import sqlite3
import stat
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .ids import ensure_engagement_uid, read_engagement_uid
from .schema import APPLICATION_ID, MIGRATIONS, SCHEMA_VERSION

EXPECTED_TABLES = frozenset(
    """engagement networks vantage_points vantage_interfaces devices addresses
    identity_claims scans host_observations observation_addresses port_observations
    script_observations topology_nodes trace_paths trace_hops manual_nodes zones
    zone_memberships topology_edges node_positions human_edits notes tags tag_links
    vantage_routes edge_decisions
    review_items review_events duplicate_proposals duplicate_proposal_events
    scope_rules audit_events raw_scan_evidence meta merge_log""".split()
)
EXPECTED_VIEWS = frozenset({"v_device_seen", "v_current_host_observations"})


class DatabaseError(RuntimeError):
    """Raised when a Lumos database is invalid or unsupported."""


def utc_now() -> str:
    """Return a consistently formatted UTC timestamp."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _configure_connection(conn: sqlite3.Connection, *, readonly: bool) -> None:
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA trusted_schema = OFF")
    conn.execute("PRAGMA busy_timeout = 5000")
    if not readonly:
        mode = conn.execute("PRAGMA journal_mode = WAL").fetchone()[0]
        if str(mode).lower() != "wal":
            raise DatabaseError(f"Could not enable WAL mode (SQLite returned {mode!r})")
        conn.execute("PRAGMA synchronous = NORMAL")


def _connect(path: Path, *, readonly: bool) -> sqlite3.Connection:
    if readonly:
        uri = path.resolve().as_uri() + "?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5.0)
    else:
        conn = sqlite3.connect(path, timeout=5.0)
    _configure_connection(conn, readonly=readonly)
    return conn


def apply_migrations(conn: sqlite3.Connection) -> None:
    """Apply all supported forward-only migrations to an empty/new database."""
    current = int(conn.execute("PRAGMA user_version").fetchone()[0])
    app_id = int(conn.execute("PRAGMA application_id").fetchone()[0])
    if app_id not in (0, APPLICATION_ID):
        raise DatabaseError(f"Wrong application_id: {app_id}")
    if current > SCHEMA_VERSION:
        raise DatabaseError(
            f"Database schema {current} is newer than supported schema {SCHEMA_VERSION}"
        )
    if current < 0:
        raise DatabaseError(f"Invalid user_version: {current}")

    for version in range(current + 1, SCHEMA_VERSION + 1):
        migration = MIGRATIONS.get(version)
        if migration is None:
            raise DatabaseError(f"Missing forward migration to schema version {version}")
        try:
            conn.executescript(
                "BEGIN EXCLUSIVE;\n"
                + migration
                + f"\nPRAGMA user_version = {version};\nCOMMIT;"
            )
        except sqlite3.Error:
            if conn.in_transaction:
                conn.rollback()
            raise


def _validate_schema(conn: sqlite3.Connection) -> None:
    objects = conn.execute(
        "SELECT type, name, sql FROM sqlite_schema "
        "WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name"
    ).fetchall()
    tables = {row[1] for row in objects if row[0] == "table"}
    views = {row[1] for row in objects if row[0] == "view"}
    triggers = [row[1] for row in objects if row[0] == "trigger"]
    virtual_tables = [
        row[1]
        for row in objects
        if row[0] == "table"
        and row[2]
        and row[2].lstrip().upper().startswith("CREATE VIRTUAL TABLE")
    ]
    if triggers:
        raise DatabaseError(f"Unexpected triggers: {', '.join(sorted(triggers))}")
    if virtual_tables:
        raise DatabaseError(f"Unexpected virtual tables: {', '.join(sorted(virtual_tables))}")
    if tables != EXPECTED_TABLES:
        missing = sorted(EXPECTED_TABLES - tables)
        extra = sorted(tables - EXPECTED_TABLES)
        raise DatabaseError(f"Unexpected table set (missing={missing}, extra={extra})")
    if views != EXPECTED_VIEWS:
        missing = sorted(EXPECTED_VIEWS - views)
        extra = sorted(views - EXPECTED_VIEWS)
        raise DatabaseError(f"Unexpected view set (missing={missing}, extra={extra})")


def validate_database(conn: sqlite3.Connection, *, integrity: bool = False) -> dict[str, Any]:
    """Validate a database's product identity and supported schema."""
    app_id = int(conn.execute("PRAGMA application_id").fetchone()[0])
    version = int(conn.execute("PRAGMA user_version").fetchone()[0])
    if app_id != APPLICATION_ID:
        raise DatabaseError(f"Wrong application_id: expected {APPLICATION_ID}, got {app_id}")
    if version != SCHEMA_VERSION:
        raise DatabaseError(f"Unsupported schema version: expected {SCHEMA_VERSION}, got {version}")
    _validate_schema(conn)
    foreign_key_errors = conn.execute("PRAGMA foreign_key_check").fetchall()
    if foreign_key_errors:
        raise DatabaseError(f"Foreign-key check failed ({len(foreign_key_errors)} violations)")
    integrity_result = None
    if integrity:
        integrity_result = str(conn.execute("PRAGMA integrity_check").fetchone()[0])
        if integrity_result != "ok":
            raise DatabaseError(f"Integrity check failed: {integrity_result}")
    return {
        "application_id": app_id,
        "user_version": version,
        "engagement_uid": read_engagement_uid(conn),
        "tables": len(EXPECTED_TABLES),
        "views": len(EXPECTED_VIEWS),
        "integrity": integrity_result,
    }


def initialize_database(path: str | os.PathLike[str], name: str) -> str:
    """Create a new owner-only engagement database; never overwrite an existing file."""
    db_path = Path(path).expanduser().absolute()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
    fd = os.open(db_path, flags, 0o600)
    os.close(fd)
    try:
        os.chmod(db_path, 0o600)
        conn = _connect(db_path, readonly=False)
        try:
            apply_migrations(conn)
            engagement_id = str(uuid.uuid4())
            with conn:
                conn.execute(
                    "INSERT INTO engagement(id, name, client, operator, created_at) "
                    "VALUES (?, ?, '', '', ?)",
                    (engagement_id, name, utc_now()),
                )
                ensure_engagement_uid(conn)
            validate_database(conn)
        finally:
            conn.close()
        # Keep the primary file private even when the process has a permissive umask.
        os.chmod(db_path, stat.S_IRUSR | stat.S_IWUSR)
        return engagement_id
    except Exception:
        for candidate in (db_path, Path(str(db_path) + "-wal"), Path(str(db_path) + "-shm")):
            try:
                candidate.unlink()
            except FileNotFoundError:
                pass
        raise


def upgrade_database(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Apply forward-only migrations to an existing engagement file.

    Refuses foreign files: application_id and the file layout are validated
    before any SQL runs, and migrations never execute SQL read from the file.
    """
    db_path = Path(path).expanduser().absolute()
    if not db_path.is_file():
        raise DatabaseError(f"Database file does not exist: {db_path}")
    conn = _connect(db_path, readonly=False)
    try:
        previous = int(conn.execute("PRAGMA user_version").fetchone()[0])
        apply_migrations(conn)
        with conn:
            ensure_engagement_uid(conn)
        result = validate_database(conn)
        result["previous_user_version"] = previous
        result["engagement_uid"] = read_engagement_uid(conn)
        return result
    finally:
        conn.close()


def open_database(path: str | os.PathLike[str], *, readonly: bool = False) -> sqlite3.Connection:
    """Open an existing Lumos DB and validate its product/schema identity."""
    db_path = Path(path).expanduser().absolute()
    if not db_path.is_file():
        raise DatabaseError(f"Database file does not exist: {db_path}")
    conn = _connect(db_path, readonly=readonly)
    try:
        validate_database(conn)
    except Exception:
        conn.close()
        raise
    return conn


def check_database(path: str | os.PathLike[str]) -> dict[str, Any]:
    """Run structural, foreign-key, and integrity checks and return a summary."""
    conn = _connect(Path(path).expanduser().absolute(), readonly=True)
    try:
        return validate_database(conn, integrity=True)
    finally:
        conn.close()
