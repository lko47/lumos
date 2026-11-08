"""Network/hostname scope matching without expanding IP ranges."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


@dataclass(frozen=True)
class TargetSpec:
    kind: str
    canonical: str
    family: int | None = None
    start: int | None = None
    end: int | None = None


@dataclass(frozen=True)
class ScopeRule:
    included: bool
    rule_kind: str
    rule_value: str


@dataclass(frozen=True)
class ScopeDecision:
    target: str
    allowed: bool
    reason: str


def _parse_ip_range(value: str) -> tuple[int, int, int] | None:
    if "-" not in value:
        return None
    left, right = value.split("-", 1)
    try:
        start = ipaddress.ip_address(left.strip())
        end = ipaddress.ip_address(right.strip())
    except ValueError:
        return None
    if start.version != end.version or int(start) > int(end):
        raise ValueError(f"Invalid IP range: {value!r}")
    return start.version, int(start), int(end)


def _normalize_hostname(value: str) -> str:
    raw = value.strip().rstrip(".")
    if not raw or len(raw) > 253 or any(char.isspace() for char in raw):
        raise ValueError(f"Invalid hostname: {value!r}")
    try:
        ascii_name = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError(f"Invalid hostname: {value!r}") from exc
    labels = ascii_name.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise ValueError(f"Invalid hostname: {value!r}")
    return ascii_name


def parse_target(value: str) -> TargetSpec:
    """Parse a literal IP, CIDR, inclusive IP range, or exact hostname."""
    raw = value.strip()
    if not raw or len(raw) > 4096:
        raise ValueError("Target is empty or too long")
    if "/" in raw:
        try:
            network = ipaddress.ip_network(raw, strict=False)
            return TargetSpec(
                "cidr", str(network), network.version, int(network.network_address), int(network.broadcast_address)
            )
        except ValueError as exc:
            raise ValueError(f"Invalid IP network: {raw!r}") from exc
    try:
        address = ipaddress.ip_address(raw)
        return TargetSpec("ip", str(address), address.version, int(address), int(address))
    except ValueError:
        pass
    ip_range = _parse_ip_range(raw)
    if ip_range is not None:
        family, start, end = ip_range
        start_ip = ipaddress.ip_address(start)
        end_ip = ipaddress.ip_address(end)
        return TargetSpec("range", f"{start_ip}-{end_ip}", family, start, end)
    if "-" in raw and ":" in raw:
        # A malformed IPv6 range should not be accepted as a DNS name.
        raise ValueError(f"Invalid IP range: {raw!r}")
    hostname = _normalize_hostname(raw)
    return TargetSpec("hostname", hostname)


def parse_scope_rule(value: str, *, included: bool) -> ScopeRule:
    target = parse_target(value)
    kind = "hostname" if target.kind == "hostname" else target.kind
    if kind == "ip":
        kind = "cidr"
        bits = 32 if target.family == 4 else 128
        canonical = f"{target.canonical}/{bits}"
    else:
        canonical = target.canonical
    return ScopeRule(included=included, rule_kind=kind, rule_value=canonical)


def _bounds(rule: ScopeRule) -> tuple[int, int, int] | None:
    if rule.rule_kind == "cidr":
        try:
            network = ipaddress.ip_network(rule.rule_value, strict=False)
        except ValueError as exc:
            raise ValueError(f"Invalid CIDR scope rule: {rule.rule_value!r}") from exc
        return network.version, int(network.network_address), int(network.broadcast_address)
    if rule.rule_kind == "range":
        parsed = _parse_ip_range(rule.rule_value)
        if parsed is None:
            raise ValueError(f"Invalid range scope rule: {rule.rule_value!r}")
        return parsed
    if rule.rule_kind == "hostname":
        return None
    raise ValueError(f"Unsupported scope rule kind: {rule.rule_kind!r}")


def _covered(start: int, end: int, intervals: list[tuple[int, int]]) -> bool:
    cursor = start
    for low, high in sorted(intervals):
        if high < cursor:
            continue
        if low > cursor:
            return False
        cursor = max(cursor, high + 1)
        if cursor > end:
            return True
    return False


def is_target_in_scope(target: str, rules: list[ScopeRule] | tuple[ScopeRule, ...]) -> ScopeDecision:
    """Allow only exact hostname rules or fully contained numeric ranges.

    Numeric containment uses integer intervals and never expands a CIDR into
    individual addresses. Any overlap with an exclusion blocks the whole target.
    """
    try:
        spec = parse_target(target)
    except ValueError as exc:
        return ScopeDecision(target, False, str(exc))

    if spec.kind == "hostname":
        included = any(r.included and r.rule_kind == "hostname" and _normalize_hostname(r.rule_value) == spec.canonical for r in rules)
        excluded = any(not r.included and r.rule_kind == "hostname" and _normalize_hostname(r.rule_value) == spec.canonical for r in rules)
        if excluded:
            return ScopeDecision(target, False, "hostname is explicitly excluded")
        if included:
            return ScopeDecision(target, True, "exact hostname allow rule")
        return ScopeDecision(target, False, "hostname is not explicitly allowlisted")

    include_intervals: list[tuple[int, int]] = []
    exclude_intervals: list[tuple[int, int]] = []
    family = spec.family
    for rule in rules:
        bounds = _bounds(rule)
        if bounds is None:
            continue
        rule_family, low, high = bounds
        if rule_family != family:
            continue
        (include_intervals if rule.included else exclude_intervals).append((low, high))

    if not _covered(spec.start, spec.end, include_intervals):
        return ScopeDecision(target, False, "target is not fully contained in included scope")
    if any(low <= spec.end and high >= spec.start for low, high in exclude_intervals):
        return ScopeDecision(target, False, "target overlaps an explicit exclusion")
    return ScopeDecision(target, True, "target is fully contained in included scope")
