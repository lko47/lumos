"""Discover the local scanner's interfaces and routes via Nmap --iflist."""

from __future__ import annotations

import ipaddress
import subprocess
from dataclasses import dataclass

from ..text import sanitize_text
from .runner import NmapRunnerError, find_nmap

MAX_IFLIST_CHARS = 1024 * 1024
IFLIST_TIMEOUT_SECONDS = 15


@dataclass(frozen=True)
class InterfaceEntry:
    name: str
    short_name: str
    address: str | None
    interface_type: str
    is_up: bool
    mtu: int
    mac: str


@dataclass(frozen=True)
class RouteEntry:
    destination: str
    device: str
    metric: int
    gateway: str | None


@dataclass(frozen=True)
class InterfaceSnapshot:
    interfaces: tuple[InterfaceEntry, ...]
    routes: tuple[RouteEntry, ...]


def parse_iflist_output(output: str) -> InterfaceSnapshot:
    """Parse Nmap's documented interface/route table; fail on unknown layouts."""
    if len(output) > MAX_IFLIST_CHARS:
        raise NmapRunnerError("Nmap --iflist output exceeded the 1 MiB safety limit")

    section: str | None = None
    interface_header = False
    route_header = False
    interfaces: list[InterfaceEntry] = []
    routes: list[RouteEntry] = []

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        marker = line.strip("*").strip().upper()
        if marker == "INTERFACES":
            section = "interfaces"
            continue
        if marker == "ROUTES":
            section = "routes"
            continue
        if section is None:
            continue

        fields = line.split()
        if section == "interfaces":
            if fields[:2] == ["DEV", "(SHORT)"]:
                interface_header = True
                continue
            if not interface_header:
                continue
            if len(fields) < 6:
                raise NmapRunnerError("Unrecognized interface row in Nmap --iflist output")
            name, short_name, raw_address, interface_type, up_text, raw_mtu = fields[:6]
            if up_text.lower() not in {"up", "down"}:
                raise NmapRunnerError("Unrecognized interface status in Nmap --iflist output")
            try:
                mtu = int(raw_mtu)
            except ValueError as exc:
                raise NmapRunnerError("Unrecognized interface MTU in Nmap --iflist output") from exc
            if mtu < 0:
                raise NmapRunnerError("Invalid interface MTU in Nmap --iflist output")
            address: str | None = None
            if raw_address.lower() not in {"(none)/0", "none", "-"}:
                try:
                    address = str(ipaddress.ip_interface(raw_address))
                except ValueError as exc:
                    raise NmapRunnerError("Invalid interface address in Nmap --iflist output") from exc
            mac = fields[6] if len(fields) > 6 else ""
            interfaces.append(
                InterfaceEntry(
                    name=sanitize_text(name, max_chars=64),
                    short_name=sanitize_text(short_name.strip("()"), max_chars=64),
                    address=address,
                    interface_type=sanitize_text(interface_type, max_chars=64),
                    is_up=up_text.lower() == "up",
                    mtu=mtu,
                    mac=sanitize_text(mac, max_chars=64),
                )
            )
        else:
            if fields[:4] == ["DST/MASK", "DEV", "METRIC", "GATEWAY"]:
                route_header = True
                continue
            if not route_header:
                continue
            if len(fields) not in {3, 4}:
                raise NmapRunnerError("Unrecognized route row in Nmap --iflist output")
            raw_destination, device, raw_metric = fields[:3]
            try:
                destination = str(ipaddress.ip_network(raw_destination, strict=False))
            except ValueError:
                if raw_destination.lower() == "default":
                    destination = "default"
                else:
                    raise NmapRunnerError("Invalid route destination in Nmap --iflist output")
            try:
                metric = int(raw_metric)
            except ValueError as exc:
                raise NmapRunnerError("Invalid route metric in Nmap --iflist output") from exc
            if metric < 0:
                raise NmapRunnerError("Invalid route metric in Nmap --iflist output")
            gateway = fields[3] if len(fields) == 4 and fields[3].lower() not in {"-", "none"} else None
            if gateway is not None:
                try:
                    gateway = str(ipaddress.ip_address(gateway))
                except ValueError as exc:
                    raise NmapRunnerError("Invalid route gateway in Nmap --iflist output") from exc
            routes.append(
                RouteEntry(
                    destination=destination,
                    device=sanitize_text(device, max_chars=64),
                    metric=metric,
                    gateway=gateway,
                )
            )

    if section is None or not interface_header or not route_header:
        raise NmapRunnerError("Nmap --iflist output did not contain both interface and route tables")
    return InterfaceSnapshot(tuple(interfaces), tuple(routes))


def discover_interfaces(executable: str | None = None) -> InterfaceSnapshot:
    """Run Nmap's local-only --iflist command; it does not scan targets."""
    nmap = find_nmap(executable)
    try:
        result = subprocess.run(
            [nmap, "--iflist"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=IFLIST_TIMEOUT_SECONDS,
            check=False,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise NmapRunnerError(f"Nmap --iflist timed out after {IFLIST_TIMEOUT_SECONDS} seconds") from exc
    except OSError as exc:
        raise NmapRunnerError(f"Could not run Nmap --iflist: {sanitize_text(exc, max_chars=512)}") from exc
    if result.returncode != 0:
        detail = sanitize_text(result.stderr or result.stdout, max_chars=1024).strip()
        suffix = f": {detail}" if detail else ""
        raise NmapRunnerError(f"Nmap --iflist failed with exit code {result.returncode}{suffix}")
    return parse_iflist_output(result.stdout)
