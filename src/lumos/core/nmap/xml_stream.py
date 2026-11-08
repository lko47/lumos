"""Bounded, incremental parser for Nmap XML output."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Callable, Iterable, Iterator, cast

from ..text import sanitize_text

MAX_XML_BYTES = 128 * 1024 * 1024
MAX_XML_DEPTH = 64
MAX_FIELD_CHARS = 4096
_FORBIDDEN_DECLARATIONS = (b"<!DOCTYPE", b"<!ENTITY")


class NmapXmlError(ValueError):
    """Nmap XML was unsafe, malformed, or exceeded a configured limit."""


class TruncatedNmapXmlError(NmapXmlError):
    """The XML document ended before its closing elements; prior hosts may exist."""


@dataclass(frozen=True)
class AddressRecord:
    kind: str
    value: str
    vendor: str = ""


@dataclass(frozen=True)
class PortRecord:
    protocol: str
    port: int
    state: str
    reason: str = ""
    service: str = ""
    product: str = ""
    version: str = ""
    tunnel: str = ""
    extra_info: str = ""


@dataclass(frozen=True)
class ScriptRecord:
    script_id: str
    output: str
    port: int | None = None


@dataclass(frozen=True)
class HopRecord:
    ttl: int
    address: str
    rtt_ms: float | None
    hostname: str = ""
    responded: bool = True


@dataclass(frozen=True)
class HostRecord:
    state: str
    reason: str
    addresses: tuple[AddressRecord, ...]
    hostnames: tuple[str, ...]
    os_name: str
    os_accuracy: int | None
    ports: tuple[PortRecord, ...]
    scripts: tuple[ScriptRecord, ...]
    hops: tuple[HopRecord, ...]
    latency_seconds: float | None = None


def _tag(element: ET.Element) -> str:
    return element.tag.rsplit("}", 1)[-1]


def _text(value: object, *, limit: int = MAX_FIELD_CHARS) -> str:
    return sanitize_text(value, max_chars=limit)


def _integer(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _float(value: str | None) -> float | None:
    try:
        result = float(value) if value is not None else None
        return result if result is not None and result >= 0 else None
    except (TypeError, ValueError):
        return None


def _children(element: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in element if _tag(child) == name]


def _first(element: ET.Element, name: str) -> ET.Element | None:
    return next((child for child in element if _tag(child) == name), None)


def _parse_host(element: ET.Element) -> HostRecord:
    status = _first(element, "status")
    state = _text(status.get("state", "unknown") if status is not None else "unknown", limit=64)
    reason = _text(status.get("reason", "") if status is not None else "", limit=256)

    addresses: list[AddressRecord] = []
    for address in _children(element, "address"):
        addrtype = address.get("addrtype", "").lower()
        kind = {"ipv4": "ipv4", "ipv6": "ipv6", "mac": "mac"}.get(addrtype)
        if kind:
            addresses.append(
                AddressRecord(
                    kind=kind,
                    value=_text(address.get("addr", ""), limit=256),
                    vendor=_text(address.get("vendor", ""), limit=512),
                )
            )

    hostnames: list[str] = []
    hostnames_element = _first(element, "hostnames")
    if hostnames_element is not None:
        for hostname in _children(hostnames_element, "hostname"):
            name = _text(hostname.get("name", ""), limit=1024)
            if name:
                hostnames.append(name)

    os_name = ""
    os_accuracy = None
    os_element = _first(element, "os")
    if os_element is not None:
        matches = _children(os_element, "osmatch")
        if matches:
            os_name = _text(matches[0].get("name", ""), limit=1024)
            os_accuracy = _integer(matches[0].get("accuracy"))

    ports: list[PortRecord] = []
    scripts: list[ScriptRecord] = []
    ports_element = _first(element, "ports")
    if ports_element is not None:
        for port_element in _children(ports_element, "port"):
            state_element = _first(port_element, "state")
            service_element = _first(port_element, "service")
            port_number = _integer(port_element.get("portid"))
            if port_number is None or not 0 <= port_number <= 65535:
                continue
            ports.append(
                PortRecord(
                    protocol=_text(port_element.get("protocol", "unknown"), limit=32).lower(),
                    port=port_number,
                    state=_text(state_element.get("state", "unknown") if state_element is not None else "unknown", limit=64),
                    reason=_text(state_element.get("reason", "") if state_element is not None else "", limit=256),
                    service=_text(service_element.get("name", "") if service_element is not None else "", limit=512),
                    product=_text(service_element.get("product", "") if service_element is not None else "", limit=512),
                    version=_text(service_element.get("version", "") if service_element is not None else "", limit=512),
                    tunnel=_text(service_element.get("tunnel", "") if service_element is not None else "", limit=128),
                    extra_info=_text(service_element.get("extrainfo", "") if service_element is not None else "", limit=1024),
                )
            )
            for script in _children(port_element, "script"):
                scripts.append(
                    ScriptRecord(
                        script_id=_text(script.get("id", "unknown"), limit=256),
                        output=_text(script.get("output", "")),
                        port=port_number,
                    )
                )

    for scripts_element in _children(element, "hostscript"):
        for script in _children(scripts_element, "script"):
            scripts.append(
                ScriptRecord(
                    script_id=_text(script.get("id", "unknown"), limit=256),
                    output=_text(script.get("output", "")),
                )
            )

    hops: list[HopRecord] = []
    trace = _first(element, "trace")
    if trace is not None:
        for hop in _children(trace, "hop"):
            ttl = _integer(hop.get("ttl"))
            if ttl is None or ttl < 1:
                continue
            address = _text(hop.get("ipaddr", ""), limit=256)
            responded = bool(address and address not in {"0.0.0.0", "::", "???"})
            hops.append(
                HopRecord(
                    ttl=ttl,
                    address=address if responded else "",
                    rtt_ms=_float(hop.get("rtt")),
                    hostname=_text(hop.get("host", ""), limit=1024),
                    responded=responded,
                )
            )

    times = _first(element, "times")
    latency_seconds = None
    if times is not None:
        srtt = _integer(times.get("srtt"))
        if srtt is not None and srtt >= 0:
            latency_seconds = srtt / 1_000_000.0

    return HostRecord(
        state=state,
        reason=reason,
        addresses=tuple(addresses),
        hostnames=tuple(hostnames),
        os_name=os_name,
        os_accuracy=os_accuracy,
        ports=tuple(ports),
        scripts=tuple(scripts),
        hops=tuple(hops),
        latency_seconds=latency_seconds,
    )


def parse_nmap_xml(
    chunks: Iterable[bytes],
    *,
    max_bytes: int = MAX_XML_BYTES,
    max_depth: int = MAX_XML_DEPTH,
    on_root: Callable[[dict[str, str]], None] | None = None,
) -> Iterator[HostRecord]:
    """Yield complete hosts as chunks arrive; reject declarations and bound resources.

    If the document is truncated after one or more complete hosts, those hosts
    have already been yielded before ``TruncatedNmapXmlError`` is raised.
    """
    parser = ET.XMLPullParser(events=("start", "end"))
    total = 0
    depth = 0
    tail = b""
    try:
        for raw_chunk in chunks:
            chunk = raw_chunk.encode("utf-8") if isinstance(raw_chunk, str) else bytes(raw_chunk)
            total += len(chunk)
            if total > max_bytes:
                raise NmapXmlError(f"Nmap XML exceeds the {max_bytes}-byte size limit")
            probe = (tail + chunk).upper()
            if any(token in probe for token in _FORBIDDEN_DECLARATIONS):
                raise NmapXmlError("DTD or entity declaration is forbidden in Nmap XML")
            tail = probe[-16:]
            parser.feed(chunk)
            for event, element in cast(Iterable[tuple[str, ET.Element]], parser.read_events()):
                if event == "start":
                    depth += 1
                    if depth > max_depth:
                        raise NmapXmlError(f"Nmap XML exceeds the {max_depth}-level nesting limit")
                    if depth == 1 and _tag(element) == "nmaprun" and on_root is not None:
                        on_root({key: _text(value, limit=MAX_FIELD_CHARS) for key, value in element.attrib.items()})
                    continue
                if _tag(element) == "host":
                    yield _parse_host(element)
                    element.clear()
                depth -= 1
        parser.close()
    except NmapXmlError:
        raise
    except ET.ParseError as exc:
        message = str(exc).lower()
        if any(token in message for token in ("no element found", "unclosed token", "unexpected end")):
            raise TruncatedNmapXmlError(f"Truncated Nmap XML: {exc}") from exc
        raise NmapXmlError(f"Malformed Nmap XML: {exc}") from exc
