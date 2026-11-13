"""Run a non-Nmap enumerator and import what it produced.

masscan and naabu are fast port *discoverers*: they say "open", never "OpenSSH
8.4". Their output is imported through the same XML path as an Nmap report, so
every observation carries the scan row, the argv and the tool version that
produced it -- provenance is not guessed, it is recorded.

Three rules hold here and are enforced by tests:

* no shell -- the command is a list, always;
* scope before packets -- an out-of-scope target never reaches subprocess;
* a missing binary is a sentence, not a traceback.
"""

from __future__ import annotations

import json
import re
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from . import engines
from .scope import is_target_in_scope
from .scope_store import get_network, read_scope_rules
from .text import sanitize_text
from .xml_import import import_nmap_xml

ENGINE_TIMEOUT_SECONDS = 1800
MASSCAN_DEFAULT_RATE = 1000
SUPPORTED_XML_ENGINES = frozenset({"masscan"})
JSON_LINE_ENGINES = frozenset({"naabu"})
GREPPABLE_ENGINES = frozenset({"rustscan"})
XML_ESCAPE = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;"}
RUSTSCAN_LINE = re.compile(r"^(?P<host>[^\s]+)\s*->\s*\[(?P<ports>[0-9,\s]*)\]")


@dataclass(frozen=True)
class EngineOptions:
    """Everything the operator chose about one engine run."""

    ports: str = ""
    rate: int = MASSCAN_DEFAULT_RATE
    operator: str | None = None
    timeout: int = ENGINE_TIMEOUT_SECONDS


class EngineScanError(RuntimeError):
    """A scan with an external engine could not be started or completed."""


def _ports_argument(ports: str) -> str:
    cleaned = sanitize_text(ports, max_chars=255).strip()
    return cleaned or "1-65535"


def masscan_argv(binary: str, target: str, ports: str, output_path: Path, rate: int) -> list[str]:
    """masscan command line writing Nmap-shaped XML to ``output_path``."""
    return [
        binary,
        target,
        "--ports", _ports_argument(ports),
        "--rate", str(max(1, int(rate))),
        "--output-format", "xml",
        "--output-filename", str(output_path),
        "--wait", "3",
    ]


def naabu_argv(binary: str, target: str, ports: str) -> list[str]:
    """naabu prints one JSON object per open port on stdout."""
    argv = [binary, "-host", target, "-silent", "-json"]
    if ports:
        argv += ["-p", _ports_argument(ports)]
    return argv


def rustscan_argv(binary: str, target: str, ports: str) -> list[str]:
    """rustscan --greppable prints ``host -> [ports]`` lines."""
    argv = [binary, "-a", target, "--greppable"]
    if ports:
        argv += ["-p", _ports_argument(ports)]
    return argv


def build_argv(engine: engines.Engine, binary: str, target: str, ports: str,
               output_path: Path, rate: int = MASSCAN_DEFAULT_RATE) -> list[str]:
    """Argument list for an engine, in the shape its output format needs."""
    if engine.name in SUPPORTED_XML_ENGINES:
        return masscan_argv(binary, target, ports, output_path, rate)
    if engine.name in JSON_LINE_ENGINES:
        return naabu_argv(binary, target, ports)
    if engine.name in GREPPABLE_ENGINES:
        return rustscan_argv(binary, target, ports)
    raise EngineScanError(f"{engine.name} output is not imported yet")


def naabu_records(output: str) -> list[dict]:
    """Parse naabu's JSON-lines output, ignoring anything malformed."""
    records = []
    for line in output.splitlines():
        stripped = line.strip()
        if not stripped.startswith("{"):
            continue
        try:
            item = json.loads(stripped)
        except ValueError:
            continue
        if not isinstance(item, dict):
            continue
        address = str(item.get("ip") or item.get("host") or "").strip()
        try:
            port = int(item.get("port"))
        except (TypeError, ValueError):
            continue
        if not address or not 0 < port < 65536:
            continue
        records.append({"address": address, "port": port,
                        "protocol": str(item.get("protocol") or "tcp").lower()})
    return records


def rustscan_records(output: str) -> list[dict]:
    """Parse rustscan's greppable ``host -> [22,80]`` lines."""
    records = []
    for line in output.splitlines():
        match = RUSTSCAN_LINE.match(line.strip())
        if not match:
            continue
        address = match.group("host").strip()
        for piece in match.group("ports").split(","):
            piece = piece.strip()
            if not piece.isdigit():
                continue
            port = int(piece)
            if 0 < port < 65536:
                records.append({"address": address, "port": port, "protocol": "tcp"})
    return records


def _escape(value: str) -> str:
    for needle, replacement in XML_ESCAPE.items():
        value = value.replace(needle, replacement)
    return value


def records_to_xml(records: list[dict], scanner: str, argv: list[str]) -> str:
    """Render port records as the Nmap-shaped XML the importer already reads.

    One evidence path beats three: whatever discovered the port, the file that
    enters the database has the same shape, and <nmaprun> records which tool
    produced it.
    """
    hosts: dict[str, list[dict]] = {}
    for record in records:
        hosts.setdefault(record["address"], []).append(record)
    lines = ['<?xml version="1.0"?>',
             f'<nmaprun scanner="{_escape(scanner)}" start="0" version="{_escape(scanner)}" '
             f'xmloutputversion="1.03" args="{_escape(" ".join(argv))}">']
    for address in sorted(hosts):
        lines.append(f'<host><address addr="{_escape(address)}" addrtype="ipv4"/><ports>')
        for record in sorted(hosts[address], key=lambda item: item["port"]):
            protocol = _escape(record.get("protocol") or "tcp")
            lines.append(
                f'<port protocol="{protocol}" portid="{record["port"]}">'
                f'<state state="open" reason="{_escape(scanner)}" reason_ttl="0"/></port>'
            )
        lines.append("</ports></host>")
    lines.append("</nmaprun>")
    return "\n".join(lines) + "\n"


def check_engine_target(database: str | Path, network: str, target: str) -> None:
    """Refuse a target outside the engagement scope, before any packet moves."""
    engagement_id, _network_id = get_network(database, network)
    decision = is_target_in_scope(target, read_scope_rules(database, engagement_id))
    if not decision.allowed:
        raise EngineScanError(
            f"{target} is outside the engagement scope; add it to scope first"
        )


def run_engine(argv: list[str], *, timeout: int = ENGINE_TIMEOUT_SECONDS) -> tuple[int, str]:
    """Run an enumerator without a shell and return (exit code, tail of its log)."""
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            shell=False,
        )
    except FileNotFoundError as exc:
        raise EngineScanError(f"{argv[0]} is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise EngineScanError(f"{argv[0]} timed out after {timeout}s") from exc
    except OSError as exc:
        raise EngineScanError(f"could not run {argv[0]}: {exc}") from exc
    log = (completed.stderr or "") + (completed.stdout or "")
    return completed.returncode, log.strip()[-2000:]


def run_engine_capture(argv: list[str], *, timeout: int = ENGINE_TIMEOUT_SECONDS) -> tuple[int, str, str]:
    """Run an engine whose report goes to stdout; returns (code, log, stdout)."""
    try:
        completed = subprocess.run(
            argv, capture_output=True, text=True, timeout=timeout, check=False, shell=False
        )
    except FileNotFoundError as exc:
        raise EngineScanError(f"{argv[0]} is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise EngineScanError(f"{argv[0]} timed out after {timeout}s") from exc
    except OSError as exc:
        raise EngineScanError(f"could not run {argv[0]}: {exc}") from exc
    return completed.returncode, (completed.stderr or "").strip()[-2000:], completed.stdout or ""


def scan_with_engine(
    database: str | Path,
    network: str,
    engine_name: str,
    target: str,
    options: EngineOptions | None = None,
) -> tuple[str, int, str]:
    """Discover ports with an external engine, then import its XML.

    Returns the same ``(scan_id, host_count, message)`` tuple as the XML
    import, so callers do not care which engine produced the evidence.
    """
    chosen = options or EngineOptions()
    engine = engines.by_name(engine_name)
    if engine is None:
        raise EngineScanError(f"unknown engine: {engine_name}")
    binary = engines.which(engine.binary)
    if binary is None:
        raise EngineScanError(f"{engine.binary} is not installed on this machine")
    cleaned_target = sanitize_text(target, max_chars=256).strip()
    if not cleaned_target:
        raise EngineScanError("a target is required")
    check_engine_target(database, network, cleaned_target)

    with tempfile.TemporaryDirectory(prefix="lumos-engine-") as directory:
        output = Path(directory) / "report.xml"
        argv = build_argv(engine, binary, cleaned_target, chosen.ports, output, chosen.rate)
        json_output = ""
        if engine.name in JSON_LINE_ENGINES or engine.name in GREPPABLE_ENGINES:
            code, log, json_output = run_engine_capture(argv, timeout=chosen.timeout)
        else:
            code, log = run_engine(argv, timeout=chosen.timeout)
        if engine.name in JSON_LINE_ENGINES or engine.name in GREPPABLE_ENGINES:
            parser = naabu_records if engine.name in JSON_LINE_ENGINES else rustscan_records
            records = parser(json_output)
            if not records:
                raise EngineScanError(
                    f"{engine.name} found no open ports (exit {code})"
                    + (f": {log}" if log else "")
                )
            output.write_text(
                records_to_xml(records, engine.name, argv), encoding="utf-8"
            )
        if not output.is_file() or output.stat().st_size == 0:
            raise EngineScanError(
                f"{engine.name} produced no report (exit {code}){': ' + log if log else ''}"
            )
        return import_nmap_xml(database, network, output, operator=chosen.operator)