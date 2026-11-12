"""Safe Nmap command construction and streaming process reader."""

from __future__ import annotations

import gzip
import hashlib
import io
import os
import selectors
import shlex
import shutil
import signal
import subprocess
import threading
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

from .xml_stream import HostRecord, NmapXmlError, parse_nmap_xml
from ..scope import parse_target
from ..text import sanitize_text

DEFAULT_XML_LIMIT = 128 * 1024 * 1024
MAX_STDERR_CHARS = 256 * 1024


class NmapRunnerError(RuntimeError):
    """Nmap could not be found, started, or parsed safely."""


@dataclass(frozen=True)
class NmapVersion:
    display: str
    stats_every: bool


@dataclass(frozen=True)
class NmapRunResult:
    exit_code: int
    hosts_seen: int
    stderr: str
    parse_error: str
    xml_bytes: int
    xml_sha256: str
    compressed_xml: bytes | None
    cancelled: bool = False


def find_nmap(executable: str | None = None) -> str:
    path = shutil.which(executable or "nmap")
    if not path:
        raise NmapRunnerError("Nmap was not found on PATH; install and use your own Nmap copy")
    return path


def inspect_nmap(executable: str) -> NmapVersion:
    """Read version/help from the user's binary without launching a scan."""
    try:
        version_run = subprocess.run(
            [executable, "--version"], capture_output=True, text=True, check=False, timeout=10, shell=False
        )
        help_run = subprocess.run(
            [executable, "--help"], capture_output=True, text=True, check=False, timeout=10, shell=False
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise NmapRunnerError(f"Could not inspect Nmap executable: {exc}") from exc
    if version_run.returncode != 0:
        raise NmapRunnerError(f"Nmap --version failed: {sanitize_text(version_run.stderr, max_chars=1024)}")
    first_line = (version_run.stdout or version_run.stderr).splitlines()
    version = sanitize_text(first_line[0] if first_line else "Nmap version unknown", max_chars=256)
    help_text = (help_run.stdout or "") + (help_run.stderr or "")
    return NmapVersion(version, "--stats-every" in help_text)


def parse_manual_options(text: str) -> list[str]:
    """Parse an option string without a shell and reject output/script escapes."""
    try:
        options = shlex.split(text, posix=True)
    except ValueError as exc:
        raise ValueError(f"Invalid Nmap option syntax: {exc}") from exc
    if options and options[0].lower() == "nmap":
        options = options[1:]
    forbidden_exact = {
        "-ox", "-oa", "-il", "--script", "--script-args", "--script-args-file",
        "-sc", "-a", "--datadir", "--exclude", "-e", "--resume", "--append-output", "--webxml",
        "--stats-every", "--",
    }
    value_options = {
        "-p", "-t", "-g", "-on", "-og", "-os", "--source-port", "--top-ports", "--port-ratio", "--host-timeout",
        "--scan-delay", "--max-scan-delay", "--max-retries", "--version-intensity", "--max-rate",
        "--ttl", "--data-length", "--dns-servers", "--spoof-mac", "--proxies", "--source-ip",
    }
    index = 0
    while index < len(options):
        item = options[index]
        lowered = item.lower()
        if lowered.startswith(("-ox", "-oa")):
            raise ValueError("Manual -oX/-oA conflicts with Lumos XML stdout; use -oN or -oG for additional output files, or remove the file-output option")
        if lowered in forbidden_exact or lowered.startswith(("--script=", "--datadir=", "--exclude=", "--resume=")):
            raise ValueError(f"Nmap option {item!r} is controlled or disabled by Lumos")
        if item.startswith("-s") and item not in {"-sS", "-sT", "-sU", "-sV"}:
            raise ValueError(f"Nmap scan mode {item!r} is not supported by the Phase 2 runner")
        if lowered.startswith(("-on", "-og", "-os")) and len(lowered) > 3:
            if item[3:] in {"-", "/dev/stdout", "/proc/self/fd/1", "/dev/fd/1"}:
                raise ValueError("Nmap text output cannot share stdout with Lumos XML")
        if lowered.startswith("-ir") or lowered.startswith("-il"):
            raise ValueError("Nmap target-list and random-target options are disabled; use scope-checked targets")
        if lowered.startswith("--min-rate") or lowered == "-t5":
            raise ValueError(f"Aggressive Nmap option {item!r} is disabled until explicit scan confirmation is implemented")
        if lowered in value_options:
            index += 1
            if index >= len(options):
                raise ValueError(f"Nmap option {item!r} requires a separate value")
            if lowered in {"-on", "-og", "-os"} and options[index] in {"-", "/dev/stdout", "/proc/self/fd/1", "/dev/fd/1"}:
                raise ValueError("Nmap text output cannot share stdout with Lumos XML")
            if options[index].startswith("-"):
                raise ValueError(f"Nmap option {item!r} requires a separate value")
        elif not item.startswith("-"):
            raise ValueError(f"Unexpected positional token {item!r} in Nmap options; targets are scope-controlled")
        index += 1
    return options


def build_nmap_argv(
    executable: str,
    targets: Sequence[str],
    *,
    options: Sequence[str] = (),
    stats_every: bool = False,
) -> list[str]:
    if not targets:
        raise ValueError("At least one target is required")
    lower_options = {item.lower() for item in options}
    tcp_scan_types = lower_options.intersection({"-ss", "-st"})
    if len(tcp_scan_types) > 1:
        raise ValueError("Select one TCP scan type; -sS and -sT cannot be combined")
    selected_scan_types = lower_options.intersection({"-ss", "-st", "-su"})
    if "--traceroute" in lower_options and (not selected_scan_types or "-st" in selected_scan_types):
        raise ValueError("Nmap traceroute is incompatible with Lumos's default/connect -sT scan; choose -sS or -sU explicitly")
    scan_type = [] if selected_scan_types else ["-sT"]
    version_detection = [] if "-sv" in lower_options else ["-sV"]
    argv = [executable, *scan_type, *version_detection, "-n", *options]
    if stats_every:
        argv.extend(("--stats-every", "5s"))
    argv.extend(("-oX", "-", *targets))
    return argv


def resolve_hostnames_with_nmap(executable: str, targets: Sequence[str]) -> list[str]:
    """Resolve explicitly scoped hostnames with an Nmap list scan, then pin IPs.

    This is a user-initiated Nmap operation (``-sL`` sends no port probes). The
    returned numeric addresses must still pass the CIDR/exclusion scope guard
    before the actual scan is started.
    """
    hostnames = [target for target in targets if _is_hostname(target)]
    if not hostnames:
        return list(targets)
    resolved: list[str] = [target for target in targets if target not in hostnames]
    argv = [executable, "-sL", "-oX", "-", *hostnames]
    records: list[HostRecord] = []
    result = run_nmap(argv, on_host=records.append, evidence=False)
    if result.exit_code != 0 or result.parse_error:
        raise NmapRunnerError(
            "Nmap hostname preflight failed: "
            + (result.parse_error or result.stderr or f"exit {result.exit_code}")
        )
    address_records = [
        record for record in records
        if any(address.kind in {"ipv4", "ipv6"} for address in record.addresses)
    ]
    if not address_records or len(address_records) < len(hostnames):
        raise NmapRunnerError("Nmap did not resolve every hostname to an IP address")
    for record in address_records:
        for address in record.addresses:
            if address.kind in {"ipv4", "ipv6"}:
                resolved.append(address.value)
    return list(dict.fromkeys(resolved))


def _is_hostname(target: str) -> bool:
    try:
        return parse_target(target).kind == "hostname"
    except ValueError:
        return False


def _process_chunks(
    process: subprocess.Popen[bytes],
    *,
    max_bytes: int,
    evidence: bool,
    stderr_parts: list[bytes],
    digest: "hashlib._Hash",
    byte_count: list[int],
    compressed: io.BytesIO | None,
    gzip_stream: gzip.GzipFile | None,
    stderr_callback: Callable[[str], None] | None,
) -> Iterable[bytes]:
    """Yield XML bytes while selecting both pipes; always drain after parser exit."""
    stdout = process.stdout
    stderr = process.stderr
    if stdout is None or stderr is None:
        raise NmapRunnerError("Nmap pipes were not created")
    selector = selectors.DefaultSelector()
    open_streams: dict[int, tuple[object, str]] = {}
    for stream, name in ((stdout, "stdout"), (stderr, "stderr")):
        selector.register(stream, selectors.EVENT_READ, name)
        open_streams[stream.fileno()] = (stream, name)

    def accept_stdout(chunk: bytes) -> None:
        byte_count[0] += len(chunk)
        if byte_count[0] > max_bytes:
            raise NmapXmlError(f"Nmap XML exceeds the {max_bytes}-byte size limit")
        digest.update(chunk)
        if gzip_stream is not None:
            gzip_stream.write(chunk)

    def accept_stderr(chunk: bytes) -> None:
        if sum(map(len, stderr_parts)) < MAX_STDERR_CHARS:
            stderr_parts.append(chunk[: MAX_STDERR_CHARS - sum(map(len, stderr_parts))])
        if stderr_callback is not None:
            stderr_callback(sanitize_text(chunk.decode("utf-8", errors="replace"), max_chars=4096))

    def drain() -> None:
        # Continue draining both pipes if XML parsing failed, preventing deadlock.
        while open_streams:
            for key, _ in selector.select(timeout=0.25):
                fd = key.fd
                stream, name = open_streams[fd]
                chunk = os.read(fd, 65536)
                if not chunk:
                    selector.unregister(fd)
                    open_streams.pop(fd, None)
                elif name == "stdout":
                    try:
                        accept_stdout(chunk)
                    except NmapXmlError:
                        # The parser has already rejected the document; drain without retaining.
                        pass
                else:
                    accept_stderr(chunk)

    try:
        while open_streams:
            for key, _ in selector.select(timeout=0.25):
                fd = key.fd
                stream, name = open_streams[fd]
                chunk = os.read(fd, 65536)
                if not chunk:
                    selector.unregister(fd)
                    open_streams.pop(fd, None)
                elif name == "stdout":
                    accept_stdout(chunk)
                    yield chunk
                else:
                    accept_stderr(chunk)
    finally:
        drain()
        selector.close()


def run_nmap(
    argv: Sequence[str],
    *,
    on_host: Callable[[HostRecord], None],
    evidence: bool = True,
    max_xml_bytes: int = DEFAULT_XML_LIMIT,
    stderr_callback: Callable[[str], None] | None = None,
    process_factory: Callable[..., subprocess.Popen[bytes]] = subprocess.Popen,
    cancel_event: threading.Event | None = None,
) -> NmapRunResult:
    """Run Nmap without a shell and stream each completed host to ``on_host``."""
    if not argv:
        raise ValueError("Nmap argv must not be empty")
    output_tokens = [
        (index, arg)
        for index, arg in enumerate(argv[1:], start=1)
        if arg.lower().startswith(("-on", "-ox", "-og", "-oa", "-os"))
    ]
    xml_tokens = [(index, arg) for index, arg in output_tokens if arg.lower().startswith("-ox") or arg.lower().startswith("-oa")]
    if len(xml_tokens) != 1:
        raise ValueError("Lumos requires exactly one Nmap XML output directed to stdout")
    output_index, output_arg = xml_tokens[0]
    if output_arg != "-oX" or output_index + 1 >= len(argv) or argv[output_index + 1] != "-":
        raise ValueError("Lumos requires -oX -; an Nmap XML file output conflicts with live streaming")
    if any(arg.lower().startswith("-oa") for _, arg in output_tokens):
        raise ValueError("Nmap -oA conflicts with Lumos XML stdout; use -oN or -oG alongside Lumos")
    for index, arg in output_tokens:
        if arg.lower().startswith(("-on", "-og", "-os")):
            destination = arg[3:] if len(arg) > 3 else (argv[index + 1] if index + 1 < len(argv) else "")
            if destination in {"-", "/dev/stdout", "/proc/self/fd/1", "/dev/fd/1"}:
                raise ValueError("Nmap text output cannot share stdout with Lumos XML")
    try:
        process = process_factory(
            list(argv), stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False, bufsize=0
        )
    except OSError as exc:
        raise NmapRunnerError(f"Could not start Nmap: {exc}") from exc
    stderr_parts: list[bytes] = []
    digest = hashlib.sha256()
    byte_count = [0]
    compressed = io.BytesIO() if evidence else None
    gzip_stream = gzip.GzipFile(fileobj=compressed, mode="wb") if compressed is not None else None
    host_count = [0]
    parse_errors: list[str] = []
    cancelled = threading.Event()

    def read_and_parse() -> None:
        chunks = _process_chunks(
            process,
            max_bytes=max_xml_bytes,
            evidence=evidence,
            stderr_parts=stderr_parts,
            digest=digest,
            byte_count=byte_count,
            compressed=compressed,
            gzip_stream=gzip_stream,
            stderr_callback=stderr_callback,
        )
        try:
            for host in parse_nmap_xml(chunks, max_bytes=max_xml_bytes):
                on_host(host)
                host_count[0] += 1
        except NmapXmlError as exc:
            parse_errors.append(sanitize_text(exc, max_chars=2048))
        finally:
            close = getattr(chunks, "close", None)
            if close:
                close()
            if gzip_stream is not None:
                gzip_stream.close()

    reader = threading.Thread(target=read_and_parse, name="lumos-nmap-reader", daemon=True)
    reader.start()
    try:
        # Poll so a caller (the TUI) can cancel without raising KeyboardInterrupt
        # into this thread.
        while reader.is_alive():
            reader.join(timeout=0.2)
            if cancel_event is not None and cancel_event.is_set() and not cancelled.is_set():
                cancelled.set()
                process.send_signal(signal.SIGINT)
    except KeyboardInterrupt:
        cancelled.set()
        process.send_signal(signal.SIGINT)
        reader.join(timeout=10)
        if reader.is_alive():
            process.kill()
            reader.join()
    exit_code = process.wait()
    if reader.is_alive():
        reader.join()
    if process.stdout:
        process.stdout.close()
    if process.stderr:
        process.stderr.close()
    return NmapRunResult(
        exit_code=exit_code,
        hosts_seen=host_count[0],
        stderr=sanitize_text(b"".join(stderr_parts).decode("utf-8", errors="replace"), max_chars=MAX_STDERR_CHARS),
        parse_error=parse_errors[0] if parse_errors else "",
        xml_bytes=byte_count[0],
        xml_sha256=digest.hexdigest(),
        compressed_xml=compressed.getvalue() if compressed is not None else None,
        cancelled=cancelled.is_set(),
    )


def redacted_argv(argv: Sequence[str]) -> list[str]:
    """Redact likely credential values before command persistence/logging."""
    result: list[str] = []
    redact_next = False
    secret_pattern = ("password", "passwd", "token", "secret", "api_key", "api-key", "apikey", "access_key", "access-key", "private_key", "private-key")
    redact_value_options = {"--script-args", "--script-args-file"}
    for arg in argv:
        if redact_next:
            result.append("<REDACTED>")
            redact_next = False
            continue
        lower = arg.lower()
        if lower in redact_value_options:
            result.append(arg)
            redact_next = True
        elif lower.startswith(("--script-args=", "--script-args-file=")):
            result.append(arg.split("=", 1)[0] + "=<REDACTED>")
        elif any(key in lower for key in secret_pattern):
            if "=" in arg:
                result.append(arg.split("=", 1)[0] + "=<REDACTED>")
            else:
                result.append(arg)
                redact_next = True
        else:
            result.append(arg)
    return result
