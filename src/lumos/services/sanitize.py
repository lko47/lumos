"""Pseudonymised engagement exports.

Sharing an engagement means handing someone a database. Handing over the real
one hands over somebody's network, so the export rewrites every address,
hostname and MAC it can find and proves afterwards that none of the originals
survive.

The mapping is *deterministic per engagement*: pseudonyms come from a hash of
the engagement id plus the original value, so two exports of the same
engagement agree, and the same host keeps the same pseudonym in a report and in
the database. Nothing in the export allows the original to be recovered.
"""

from __future__ import annotations

import gzip
import hashlib
import hmac
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path

from ..core.database import open_database
from ..core.merge import _identifier  # one validated-identifier rule for SQL

SALT_SUFFIX = b"lumos-sanitize-v1"
EXPORT_RANGES = ("192.0.2.", "198.51.100.", "203.0.113.")
IPV6_PREFIX = "2001:db8:"
MAC_PREFIX = "02:00:"
HOSTNAME_SUFFIX = ".example"
BATCH = 200

# Every TEXT column of every table is rewritten, not a hand-picked list: the
# first version named eight columns and leaked through eight others (zones.cidr,
# host_observations.raw_host_json, topology_nodes.entity_id ...).


def _text_columns(conn: sqlite3.Connection) -> dict[str, tuple[str, ...]]:
    """table -> its TEXT columns, from the schema as it actually is."""
    tables: dict[str, tuple[str, ...]] = {}
    names = [
        str(row[0])
        for row in conn.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'"
            " AND name NOT LIKE 'sqlite_%' ORDER BY name"
        )
    ]
    for table in names:
        columns = [
            str(row[1])
            for row in conn.execute(f"PRAGMA table_info({_identifier(table)})")
            if str(row[2]).upper() == "TEXT"
        ]
        if columns:
            tables[table] = tuple(columns)
    return tables


class SanitizeError(ValueError):
    """An export that cannot be produced safely, with the reason in the sentence."""


@dataclass(frozen=True)
class SanitizeStats:
    addresses: int = 0
    hostnames: int = 0
    macs: int = 0
    networks: int = 0
    rewritten_values: int = 0
    evidence_rewritten: int = 0

    @property
    def total(self) -> int:
        return self.addresses + self.hostnames + self.macs + self.networks


def _salt(engagement_id: str) -> bytes:
    return hashlib.sha256((engagement_id + SALT_SUFFIX.decode()).encode()).digest()


def _digest(salt: bytes, value: str) -> bytes:
    return hmac.new(salt, value.encode("utf-8", "replace"), hashlib.sha256).digest()


def _ipv4_pseudonym(salt: bytes, value: str) -> str:
    digest = _digest(salt, value)
    base = EXPORT_RANGES[digest[0] % len(EXPORT_RANGES)]
    # Each range already carries three octets, so exactly one is appended; 0 and
    # 255 stay out so every mapping is a usable host address.
    return f"{base}{digest[1] % 254 + 1}"


def _ipv6_pseudonym(salt: bytes, value: str) -> str:
    digest = _digest(salt, value)
    return f"{IPV6_PREFIX}{digest.hex()[:16]}"


def _mac_pseudonym(salt: bytes, value: str) -> str:
    digest = _digest(salt, value)
    return MAC_PREFIX + ":".join(f"{byte:02x}" for byte in digest[:4])


def _hostname_pseudonym(salt: bytes, value: str) -> str:
    return "host-" + _digest(salt, value).hex()[:10] + HOSTNAME_SUFFIX


def _network_pseudonym(salt: bytes, value: str) -> str:
    base, _, prefix = value.partition("/")
    mapped = _ipv4_pseudonym(salt, base) if ":" not in base else _ipv6_pseudonym(salt, base)
    return f"{mapped}/{prefix}" if prefix else mapped


_KIND_BY_SHAPE = (
    (re.compile(r"^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$"), "mac"),
    (re.compile(r"^[0-9A-Fa-f:]+$"), "ipv6"),
    (re.compile(r"^\d{1,3}(\.\d{1,3}){3}$"), "ipv4"),
    (re.compile(r"^[0-9A-Za-z._-]+$"), "hostname"),
)


def _classify(value: str) -> str:
    for pattern, kind in _KIND_BY_SHAPE:
        if pattern.match(value):
            return kind
    return ""


def _pseudonym(salt: bytes, kind: str, value: str) -> str:
    if kind == "ipv4":
        return _ipv4_pseudonym(salt, value)
    if kind == "ipv6":
        return _ipv6_pseudonym(salt, value)
    if kind == "mac":
        return _mac_pseudonym(salt, value)
    return _hostname_pseudonym(salt, value)


def _collect(conn: sqlite3.Connection) -> dict[str, set[str]]:
    """Every original value the export must not carry."""
    found: dict[str, set[str]] = {"ipv4": set(), "ipv6": set(), "mac": set(), "hostname": set()}

    def add(value: object, *, forced: str = "") -> None:
        text = str(value or "").strip()
        if not text:
            return
        kind = forced or _classify(text)
        if kind:
            found[kind].add(text)

    for normalized, display in conn.execute(
        "SELECT normalized_value, display_value FROM addresses"
    ):
        add(normalized)
        add(display)
    for kind, value in conn.execute("SELECT kind, normalized_value FROM addresses"):
        add(value, forced=str(kind) if str(kind) in found else "")
    for (cidr,) in conn.execute("SELECT cidr FROM networks"):
        add(str(cidr).split("/")[0])
    for (hostname,) in conn.execute(
        "SELECT hostname FROM host_observations WHERE hostname <> ''"
    ):
        add(hostname, forced="hostname")
    for address, mac in conn.execute("SELECT address, mac FROM vantage_interfaces"):
        add(address)
        add(mac)
    for (label,) in conn.execute("SELECT label FROM topology_nodes"):
        add(label)
    return found


def build_mapping(conn: sqlite3.Connection, engagement_id: str) -> dict[str, str]:
    """Original value -> pseudonym, deterministic per engagement and value."""
    salt = _salt(engagement_id)
    collected = _collect(conn)
    # A pseudonym must not equal any original value: both live in the same
    # documentation ranges, so a rewrite that lands on another host's real
    # address would leave that address in the export. The proof pass caught this
    # roughly one run in ten before the originals were excluded.
    originals = {value for values in collected.values() for value in values}
    used: set[str] = set()
    mapping: dict[str, str] = {}
    for kind, values in collected.items():
        for value in sorted(values):
            candidate = _pseudonym(salt, kind, value)
            attempt = 0
            while candidate in used or candidate in originals:
                attempt += 1
                candidate = _pseudonym(salt, kind, f"{value}#{attempt}")
            used.add(candidate)
            mapping[value] = candidate
    return mapping


def _rewrite_text(text: str, mapping: dict[str, str]) -> tuple[str, int]:
    """Replace every mapped original, longest first, as whole tokens where possible."""
    hits = 0
    for original in sorted(mapping, key=len, reverse=True):
        if original not in text:
            continue
        pattern = re.compile(r"(?<![\w.:-])" + re.escape(original) + r"(?![\w.:-])")
        text, count = pattern.subn(mapping[original], text)
        if count == 0 and original in text:
            text = text.replace(original, mapping[original])
            count = 1
        hits += count
    return text, hits


def _column_names(conn: sqlite3.Connection, table: str) -> list[str]:
    _identifier(table)
    return [str(row[1]) for row in conn.execute(f"PRAGMA table_info({table})")]


def _rewrite_table(
    conn: sqlite3.Connection, table: str, columns: tuple[str, ...], mapping: dict[str, str]
) -> int:
    present = set(_column_names(conn, table))
    usable = [name for name in columns if name in present]
    if not usable:
        return 0
    for name in usable:
        _identifier(name)
    selected = ", ".join(("rowid", *usable))
    updated = 0
    rows = conn.execute(f"SELECT {selected} FROM {table}").fetchall()
    for row in rows:
        rowid = row[0]
        values = list(row[1:])
        changed = False
        hits = 0
        for index, value in enumerate(values):
            if not isinstance(value, str):
                continue
            replaced, count = _rewrite_text(value, mapping)
            if count:
                values[index] = replaced
                hits += count
                changed = True
        if not changed:
            continue
        assignments = ", ".join(f"{name} = ?" for name in usable)
        conn.execute(f"UPDATE {table} SET {assignments} WHERE rowid = ?", (*values, rowid))
        updated += hits
    return updated


def _rewrite_evidence(conn: sqlite3.Connection, mapping: dict[str, str]) -> int:
    """Stored Nmap XML is the most detailed copy of the network; rewrite it too."""
    rewritten = 0
    rows = conn.execute(
        "SELECT scan_id, compression, payload FROM raw_scan_evidence"
    ).fetchall()
    for scan_id, compression, payload in rows:
        raw = bytes(payload)
        try:
            text = gzip.decompress(raw).decode("utf-8") if compression == "gzip" else raw.decode(
                "utf-8"
            )
        except (OSError, UnicodeDecodeError):
            continue  # not text we can rewrite; the caller's proof check will catch leaks
        replaced, hits = _rewrite_text(text, mapping)
        if not hits:
            continue
        body = replaced.encode("utf-8")
        blob = gzip.compress(body) if compression == "gzip" else body
        conn.execute(
            "UPDATE raw_scan_evidence SET payload = ?, byte_length = ?, sha256 = ?"
            " WHERE scan_id = ?",
            (blob, len(body), hashlib.sha256(body).hexdigest(), scan_id),
        )
        rewritten += hits
    return rewritten


def _leaks(database: Path, mapping: dict[str, str]) -> list[str]:
    """Prove the export does not carry the originals."""
    conn = open_database(database, readonly=True)
    try:
        text = "\n".join(
            str(value)
            for table, columns in _text_columns(conn).items()
            for column in columns
            for (value,) in conn.execute(
                f"SELECT {_identifier(column)} FROM {_identifier(table)}"
            )
        )
        evidence = "\n".join(
            (gzip.decompress(bytes(payload)) if compression == "gzip" else bytes(payload)).decode(
                "utf-8", "replace"
            )
            for compression, payload in conn.execute(
                "SELECT compression, payload FROM raw_scan_evidence"
            )
        )
    finally:
        conn.close()
    haystack = text + "\n" + evidence
    return [original for original in mapping if original in haystack]


def export_sanitised(
    database: str | Path, output: str | Path, *, overwrite: bool = False
) -> SanitizeStats:
    """Copy the engagement with every identity rewritten; source untouched."""
    source = Path(database)
    target = Path(output)
    if not source.is_file():
        raise SanitizeError(f"no database at {source}")
    if source.resolve() == target.resolve():
        raise SanitizeError("the export cannot overwrite its source")
    if target.exists() and not overwrite:
        raise SanitizeError(f"{target} exists; pass overwrite to replace it")
    target.parent.mkdir(parents=True, exist_ok=True)

    read = open_database(source, readonly=True)
    try:
        row = read.execute("SELECT id FROM engagement LIMIT 1").fetchone()
        if row is None:
            raise SanitizeError("the source database has no engagement")
        engagement_id = str(row[0])
        mapping = build_mapping(read, engagement_id)
        counts = {kind: len(values) for kind, values in _collect(read).items()}
        network_count = read.execute("SELECT COUNT(*) FROM networks").fetchone()[0]
    finally:
        read.close()

    target.unlink(missing_ok=True)
    copy = sqlite3.connect(source)
    try:
        destination = sqlite3.connect(target)
        try:
            copy.backup(destination)
        finally:
            destination.close()
    finally:
        copy.close()

    conn = open_database(target)
    try:
        with conn:
            hits = sum(
                _rewrite_table(conn, table, columns, mapping)
                for table, columns in _text_columns(conn).items()
            )
            evidence = _rewrite_evidence(conn, mapping)
    finally:
        conn.close()
    try:
        target.chmod(0o600)
    except OSError:
        pass

    leaks = _leaks(target, mapping)
    if leaks:  # pragma: no cover - only reachable if a new column escapes TEXT_COLUMNS
        raise SanitizeError(
            f"the export still carries {len(leaks)} original value(s);"
            " the rewrite and the proof disagree, so nothing was shipped"
        )
    return SanitizeStats(
        addresses=counts["ipv4"] + counts["ipv6"],
        hostnames=counts["hostname"],
        macs=counts["mac"],
        networks=int(network_count or 0),
        rewritten_values=hits,
        evidence_rewritten=evidence,
    )
