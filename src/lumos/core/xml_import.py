"""Safe streaming import of Nmap XML into an engagement database."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import shlex
import getpass
from datetime import datetime, timezone
from pathlib import Path
import xml.etree.ElementTree as ET

from .database import open_database, utc_now
from .nmap.runner import redacted_argv
from .nmap.xml_stream import MAX_XML_BYTES, NmapXmlError, parse_nmap_xml
from .scan_store import ScanWriter, make_scan_context
from .scope_store import get_network, read_scope_rules
from .text import sanitize_text


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _read_root_attributes(path: Path, max_bytes: int) -> dict[str, str]:
    parser = ET.XMLPullParser(events=("start",))
    total = 0
    tail = b""
    with path.open("rb") as stream:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            total += len(chunk)
            if total > max_bytes:
                raise NmapXmlError(f"Nmap XML exceeds the {max_bytes}-byte size limit")
            probe = (tail + chunk).upper()
            if b"<!DOCTYPE" in probe or b"<!ENTITY" in probe:
                raise NmapXmlError("DTD or entity declaration is forbidden in Nmap XML")
            tail = probe[-16:]
            try:
                parser.feed(chunk)
                for _, element in parser.read_events():
                    if _local_name(element.tag) != "nmaprun":
                        raise NmapXmlError("XML root element is not nmaprun")
                    return {key: sanitize_text(value, max_chars=4096) for key, value in element.attrib.items()}
            except ET.ParseError as exc:
                raise NmapXmlError(f"Malformed Nmap XML header: {exc}") from exc
    raise NmapXmlError("Nmap XML has no nmaprun root element")


def _start_time(value: str) -> str:
    try:
        seconds = float(value)
        return datetime.fromtimestamp(seconds, timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")
    except (ValueError, OverflowError, OSError):
        return utc_now()


def _compress_file(path: Path, max_bytes: int, enabled: bool) -> tuple[bytes | None, int, str]:
    digest = hashlib.sha256()
    compressed = io.BytesIO() if enabled else None
    gzip_stream = gzip.GzipFile(fileobj=compressed, mode="wb") if compressed is not None else None
    count = 0
    with path.open("rb") as stream:
        while chunk := stream.read(65536):
            count += len(chunk)
            if count > max_bytes:
                if gzip_stream:
                    gzip_stream.close()
                raise NmapXmlError(f"Nmap XML exceeds the {max_bytes}-byte size limit")
            digest.update(chunk)
            if gzip_stream:
                gzip_stream.write(chunk)
    if gzip_stream:
        gzip_stream.close()
    return compressed.getvalue() if compressed is not None else None, count, digest.hexdigest()


def import_nmap_xml(
    database_path: str | Path,
    network_name: str,
    xml_path: str | Path,
    *,
    operator: str | None = None,
    evidence: bool = True,
    max_xml_bytes: int = MAX_XML_BYTES,
) -> tuple[str, int, str]:
    """Import XML incrementally; complete hosts survive malformed/truncated tails."""
    source = Path(xml_path)
    if not source.is_file():
        raise FileNotFoundError(source)
    if source.stat().st_size > max_xml_bytes:
        raise NmapXmlError(f"Nmap XML exceeds the {max_xml_bytes}-byte size limit")
    root = _read_root_attributes(source, max_xml_bytes)
    nmap_args = root.get("args", "")
    try:
        args = redacted_argv(shlex.split(nmap_args)) if nmap_args else []
    except ValueError:
        args = []
    if not args:
        args = ["nmap-xml-import"]

    engagement_id, network_id = get_network(database_path, network_name)
    scope_rules = read_scope_rules(database_path, engagement_id)
    conn = open_database(database_path, readonly=True)
    try:
        row = conn.execute("SELECT operator FROM engagement WHERE id = ?", (engagement_id,)).fetchone()
        engagement_operator = row[0] if row else ""
    finally:
        conn.close()
    operator_name = sanitize_text(operator or engagement_operator or getpass.getuser(), max_chars=256)
    context = make_scan_context(
        engagement_id=engagement_id,
        network_id=network_id,
        targets=[source.name],
        resolved_targets=[],
        argv=args,
        nmap_version=root.get("version", "unknown"),
        scanner_name=f"XML import: {sanitize_text(source.name, max_chars=256)}",
        operator=operator_name,
        interface="",
        scope_override=False,
        evidence_enabled=evidence,
    )
    context["scope_rules"] = scope_rules
    context["started_at"] = _start_time(root.get("start", ""))
    context["event_started"] = "xml_import_started"
    context["event_finished"] = "xml_import_finished"
    context["targets_json"] = json.dumps({"source_file": source.name}, ensure_ascii=False)
    compressed, byte_length, sha256 = _compress_file(source, max_xml_bytes, evidence)
    writer = ScanWriter(database_path, context)
    parse_error = ""
    host_count = 0
    try:
        with source.open("rb") as stream:
            chunks = iter(lambda: stream.read(65536), b"")
            for host in parse_nmap_xml(chunks, max_bytes=max_xml_bytes):
                writer.submit_host(host)
                host_count += 1
    except NmapXmlError as exc:
        parse_error = sanitize_text(exc, max_chars=2048)
    status = "failed" if parse_error else "completed"
    writer.finish(
        exit_code=None,
        status=status,
        evidence=compressed,
        evidence_bytes=byte_length,
        evidence_sha256=sha256,
        detail=parse_error or f"Imported from {source.name}",
    )
    return context["scan_id"], host_count, parse_error
