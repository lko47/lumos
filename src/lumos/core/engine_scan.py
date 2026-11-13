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


def build_argv(engine: engines.Engine, binary: str, target: str, ports: str,
               output_path: Path, rate: int = MASSCAN_DEFAULT_RATE) -> list[str]:
    """Argument list for an engine; only engines with an XML writer are accepted."""
    if engine.name not in SUPPORTED_XML_ENGINES:
        raise EngineScanError(
            f"{engine.name} output is not imported yet; only masscan XML is wired"
        )
    return masscan_argv(binary, target, ports, output_path, rate)


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
        code, log = run_engine(argv, timeout=chosen.timeout)
        if not output.is_file() or output.stat().st_size == 0:
            raise EngineScanError(
                f"{engine.name} produced no report (exit {code}){': ' + log if log else ''}"
            )
        return import_nmap_xml(database, network, output, operator=chosen.operator)