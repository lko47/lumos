"""Scope-checked orchestration of one user-initiated Nmap scan."""

from __future__ import annotations

import getpass
import socket
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Sequence

from .database import open_database
from .nmap.iflist import discover_interfaces
from .nmap.runner import (
    NmapRunResult,
    build_nmap_argv,
    find_nmap,
    inspect_nmap,
    parse_manual_options,
    resolve_hostnames_with_nmap,
    run_nmap,
)
from .scope import ScopeRule, is_target_in_scope, parse_target
from .scope_store import get_network, read_scope_rules
from .scan_store import (
    ScanWriter,
    acquire_scan_lock,
    make_scan_context,
    reconcile_interrupted_scans,
    release_scan_lock,
)
from .text import sanitize_text


class ScopeConfirmationRequired(ValueError):
    def __init__(self, targets: list[str], confirmation_text: str):
        self.targets = targets
        self.confirmation_text = confirmation_text
        super().__init__("Out-of-scope scan requires explicit confirmation: " + confirmation_text)


@dataclass(frozen=True)
class ScanOutcome:
    scan_id: str
    result: NmapRunResult
    command: tuple[str, ...]
    resolved_targets: tuple[str, ...]
    scope_override: bool


def _check_target_scope(targets: Sequence[str], rules: list[ScopeRule]) -> list[str]:
    outside: list[str] = []
    for target in targets:
        decision = is_target_in_scope(target, rules)
        if not decision.allowed:
            outside.append(target)
    return outside


def _scope_phrase(targets: list[str]) -> str:
    return "SCAN OUT OF SCOPE: " + ", ".join(sorted(set(targets)))


def scan_database(
    database_path: str | Path,
    network_name: str,
    targets: Sequence[str],
    *,
    nmap_options: str = "",
    interface: str = "",
    operator: str | None = None,
    executable: str | None = None,
    evidence: bool = True,
    scope_confirmation: str = "",
    on_command: Callable[[Sequence[str]], None] | None = None,
    on_progress: Callable[[str], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> ScanOutcome:
    """Validate scope, launch Nmap without a shell, and stream results to SQLite."""
    if not targets:
        raise ValueError("At least one target is required")
    normalized_targets = [target.strip() for target in targets]
    if any(not target for target in normalized_targets):
        raise ValueError("Targets must not be empty")
    for target in normalized_targets:
        parse_target(target)  # Strict syntax validation happens before process launch.
    # A previous run killed mid-scan leaves its row 'running'; nothing else
    # would ever clear it when no scanner process holds the lock.
    reconcile_interrupted_scans(database_path)

    engagement_id, network_id = get_network(database_path, network_name)
    scope_rules = read_scope_rules(database_path, engagement_id)
    nmap = find_nmap(executable)
    version = inspect_nmap(nmap)
    options = parse_manual_options(nmap_options)
    interface = sanitize_text(interface, max_chars=256).strip()
    if interface:
        options.extend(("-e", interface))

    hostnames = [target for target in normalized_targets if parse_target(target).kind == "hostname"]
    non_hostnames = [target for target in normalized_targets if target not in hostnames]
    outside = _check_target_scope(non_hostnames, scope_rules)
    for hostname in hostnames:
        decision = is_target_in_scope(hostname, scope_rules)
        if not decision.allowed:
            raise ValueError(
                f"Hostname {hostname!r} must have an exact allow rule before resolution; {decision.reason}"
            )
    if outside:
        phrase = _scope_phrase(outside)
        if scope_confirmation != phrase:
            raise ScopeConfirmationRequired(outside, phrase)
    scope_override = bool(outside)

    if hostnames:
        if on_command is not None:
            on_command([nmap, "-sL", "-oX", "-", *hostnames])
        resolved_targets = resolve_hostnames_with_nmap(nmap, normalized_targets)
    else:
        resolved_targets = list(normalized_targets)

    resolved_outside = _check_target_scope(resolved_targets, scope_rules)
    if resolved_outside:
        phrase = _scope_phrase(resolved_outside)
        if scope_confirmation != phrase:
            raise ScopeConfirmationRequired(resolved_outside, phrase)
        scope_override = True

    argv = build_nmap_argv(
        nmap,
        resolved_targets,
        options=options,
        stats_every=version.stats_every,
    )
    if on_command is not None:
        on_command(argv)

    conn = open_database(database_path, readonly=True)
    try:
        row = conn.execute("SELECT operator FROM engagement WHERE id = ?", (engagement_id,)).fetchone()
        engagement_operator = row[0] if row else ""
    finally:
        conn.close()
    operator_name = sanitize_text(operator or engagement_operator or getpass.getuser(), max_chars=256)
    scanner_name = sanitize_text(socket.gethostname(), max_chars=512)
    context = make_scan_context(
        engagement_id=engagement_id,
        network_id=network_id,
        targets=normalized_targets,
        resolved_targets=resolved_targets,
        argv=argv,
        nmap_version=version.display,
        scanner_name=scanner_name,
        operator=operator_name,
        interface=interface,
        scope_override=scope_override,
        evidence_enabled=evidence,
    )
    context["scope_rules"] = scope_rules
    # Capture the routing table the scan actually ran on. Without it the
    # inference engine cannot tell a connected network from a routed one, and a
    # laptop that changed networks would keep confidently wrong links.
    try:
        context["iflist"] = discover_interfaces(nmap)
    except Exception:  # --iflist is best-effort; never abort a scan for it
        context["iflist"] = None
    writer = ScanWriter(database_path, context)
    scan_lock = acquire_scan_lock(database_path)
    try:
        try:
            result = run_nmap(
                argv,
                on_host=writer.submit_host,
                evidence=evidence,
                stderr_callback=on_progress,
                cancel_event=cancel_event,
            )
        except BaseException as exc:
            writer.finish(
                exit_code=-1,
                status="failed",
                evidence=None,
                evidence_bytes=0,
                evidence_sha256="",
                detail=sanitize_text(exc, max_chars=4096),
            )
            raise

        if result.cancelled:
            status = "cancelled"
        elif result.exit_code != 0 or result.parse_error:
            status = "failed"
        else:
            status = "completed"
        writer.finish(
            exit_code=result.exit_code,
            status=status,
            evidence=result.compressed_xml,
            evidence_bytes=result.xml_bytes,
            evidence_sha256=result.xml_sha256,
            detail=result.parse_error or result.stderr,
        )
    finally:
        release_scan_lock(scan_lock)
    if status == "completed":
        # Derive the inferred links from the stored interface/route facts. This
        # runs on its own connection after the writer thread closed, and a
        # failure here must never turn a successful scan into a failed one.
        try:
            from .inference import rebuild_inferred

            rebuild_inferred(database_path)
        except Exception:
            pass
    return ScanOutcome(context["scan_id"], result, tuple(argv), tuple(resolved_targets), scope_override)
