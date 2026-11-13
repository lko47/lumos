"""External enumerators Lumos can drive, and what each one actually knows.

Facts only: this module never runs anything.  It answers three questions the
interface and the scanning layer both need -- which binaries exist, what each
one is capable of, and which ones the operator enabled -- so a missing tool is
a drawn checkbox rather than a traceback halfway through an assessment.

No shell, ever: every command leaves here as an argument list.
"""

from __future__ import annotations

import json
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

# Capability names used across the interface.  A capability is a promise about
# the data, not marketing: only nmap can turn a port into a service.
PORT_SCAN = "port-scan"
SERVICE = "service"
OPERATING_SYSTEM = "operating-system"
TRACEROUTE = "traceroute"
XML = "xml"
JSON_OUT = "json"
FAST = "fast"

SETTINGS_VERSION = 1


@dataclass(frozen=True)
class Engine:
    """One external tool, and the honest description of what it gives us."""

    name: str
    binary: str
    capabilities: frozenset[str]
    note: str
    argument_style: str = "nmap"

    @property
    def enumerates_services(self) -> bool:
        return SERVICE in self.capabilities

    def argv(self, target: str, ports: str = "") -> list[str]:
        """Command line for a discovery run; the caller adds any output path."""
        if not target:
            raise ValueError("a target is required")
        if self.name == "masscan":
            argv = [self.binary, target, "--ports", ports or "1-65535", "--rate", "1000"]
            return argv
        if self.name == "naabu":
            argv = [self.binary, "-host", target, "-silent", "-json"]
            if ports:
                argv += ["-p", ports]
            return argv
        if self.name == "rustscan":
            argv = [self.binary, "-a", target, "--greppable"]
            if ports:
                argv += ["-p", ports]
            return argv
        argv = ["nmap", "-oX", "-", "-Pn"]
        if ports:
            argv += ["-p", ports]
        return argv + [target]


ENGINES: tuple[Engine, ...] = (
    Engine(
        "nmap",
        "nmap",
        frozenset({PORT_SCAN, SERVICE, OPERATING_SYSTEM, TRACEROUTE, XML}),
        "Authoritative: XML import, service and OS detection, traceroute.",
    ),
    Engine(
        "masscan",
        "masscan",
        frozenset({PORT_SCAN, FAST}),
        "Speed only: no service detection, needs its own XML/JSON import.",
    ),
    Engine(
        "naabu",
        "naabu",
        frozenset({PORT_SCAN, FAST, JSON_OUT}),
        "Fast port discovery; service detection is handed to nmap.",
    ),
    Engine(
        "rustscan",
        "rustscan",
        frozenset({PORT_SCAN, FAST}),
        "Fast port discovery; can hand open ports to nmap for -sV.",
    ),
)


def by_name(name: str) -> Engine | None:
    """Look an engine up case-insensitively; unknown names are not fatal."""
    wanted = name.strip().lower()
    for engine in ENGINES:
        if engine.name == wanted:
            return engine
    return None


def which(binary: str) -> str | None:
    """Absolute path of an installed binary, or None. Never invokes a shell."""
    return shutil.which(binary)


def detect() -> dict[str, str | None]:
    """Map every known engine to its absolute path (or None when absent)."""
    return {engine.name: which(engine.binary) for engine in ENGINES}


@dataclass(frozen=True)
class EngineStatus:
    """What the settings page shows: installed, enabled, and what it can do."""

    name: str
    path: str | None
    enabled: bool
    capabilities: tuple[str, ...]
    note: str

    @property
    def installed(self) -> bool:
        return self.path is not None

    @property
    def selectable(self) -> bool:
        return self.installed

    def checkbox(self) -> str:
        return "[x]" if self.enabled else "[ ]"


def settings_path() -> Path:
    """``$XDG_CONFIG_HOME/lumos/settings.json`` (ignored when malformed)."""
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "lumos" / "settings.json"


def load_enabled(path: Path | None = None) -> frozenset[str]:
    """Names of engines the operator enabled; every installed engine by default.

    A broken settings file must never stop an assessment, so any read or parse
    failure falls back to "everything installed is enabled".
    """
    target = path or settings_path()
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
        names = raw.get("enabled_engines")
    except (OSError, ValueError, AttributeError):
        return frozenset(name for name, found in detect().items() if found)
    if not isinstance(names, list):
        return frozenset(name for name, found in detect().items() if found)
    return frozenset(str(name) for name in names if isinstance(name, str))


def save_enabled(names: frozenset[str] | set[str], path: Path | None = None) -> Path:
    """Persist the enabled engines; returns the file written."""
    target = path or settings_path()
    target.parent.mkdir(parents=True, exist_ok=True)
    payload = {"version": SETTINGS_VERSION, "enabled_engines": sorted(names)}
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return target


def statuses(path: Path | None = None) -> tuple[EngineStatus, ...]:
    """The full settings-page model, in a stable order."""
    found = detect()
    enabled = load_enabled(path)
    return tuple(
        EngineStatus(
            name=engine.name,
            path=found.get(engine.name),
            enabled=engine.name in enabled and found.get(engine.name) is not None,
            capabilities=tuple(sorted(engine.capabilities)),
            note=engine.note,
        )
        for engine in ENGINES
    )


@dataclass
class _Prefs:
    enabled: set[str] = field(default_factory=set)


def toggle(name: str, path: Path | None = None) -> tuple[EngineStatus, ...]:
    """Flip one engine's checkbox and save; refusing engines that are absent."""
    engine = by_name(name)
    if engine is None or which(engine.binary) is None:
        return statuses(path)
    current = set(load_enabled(path))
    current.symmetric_difference_update({engine.name})
    save_enabled(current, path)
    return statuses(path)