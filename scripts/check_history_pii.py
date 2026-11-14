#!/usr/bin/env python3
"""Fail when the git history carries personal data, not just the working tree.

`tests/test_repo_hygiene.py` checks the files on disk; a file can be sanitised
today while the old bytes stay reachable through an earlier commit or tag. This
walks every revision, every commit message and every author identity.

Usage:
    python3 scripts/check_history_pii.py [--repo PATH] [--quiet]

Exit codes: 0 clean, 1 findings, 2 not a git repository or no history.
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# Reserved documentation ranges and loopback are the placeholders we rewrite TO,
# so they are the only addresses that may appear.
# These must stay POSIX ERE: `git grep -E` has no lookahead and no lookbehind.
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private 10/8 host", re.compile(r"10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}")),
    ("private 192.168/16 host", re.compile(r"192\.168\.[0-9]{1,3}\.[0-9]{1,3}")),
    ("private 172.16-31 host", re.compile(r"172\.(1[6-9]|2[0-9]|3[01])\.[0-9]{1,3}\.[0-9]{1,3}")),
    ("home directory path", re.compile(r"/home/[a-z0-9._-]+")),
)

# Placeholders that tests use on purpose. Anything not listed is a finding.
ALLOWED_HOSTS = {
    "10.0.0.0", "10.0.0.1", "10.0.0.2", "10.0.0.5", "10.0.0.6", "10.0.0.9",
    "10.0.0.10", "10.0.0.11", "10.0.0.12", "10.0.0.13", "10.0.0.20",
    "10.9.9.9",
}
# Ranges the test fixtures invent on purpose: a fabricated office LAN and the
# Docker default bridge. Naming prefixes here keeps the rule honest and short.
ALLOWED_PREFIXES = ("10.8.0.", "172.17.0.")
ALLOWED_PATHS = {"/home/user"}


def _git(repo: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args], cwd=repo, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        raise SystemExit(f"git {' '.join(args)} failed: {result.stderr.strip()}")
    return result.stdout


def revisions(repo: Path) -> list[str]:
    return _git(repo, "rev-list", "--all").split()


def _allowed(value: str) -> bool:
    """Placeholders the suite uses on purpose are not findings."""
    if value.startswith("/home/"):
        return value in ALLOWED_PATHS
    if value in ALLOWED_HOSTS:
        return True
    return value.startswith(ALLOWED_PREFIXES)


def scan_blobs(repo: Path, revs: list[str]) -> list[str]:
    findings: list[str] = []
    expression = "|".join(pattern.pattern for _label, pattern in PATTERNS)
    for rev in revs:
        result = subprocess.run(
            ["git", "grep", "-nI", "-E", "-e", expression, rev],
            cwd=repo, capture_output=True, text=True, check=False,
        )
        if result.returncode not in (0, 1):
            raise SystemExit(f"git grep failed on {rev[:8]}: {result.stderr.strip()}")
        out = result.stdout
        for line in out.splitlines():
            parts = line.split(":", 3)
            if len(parts) < 4:
                continue
            _sha, path, number, text = parts
            for label, pattern in PATTERNS:
                for match in pattern.finditer(text):
                    candidate = match.group(0)
                    if _allowed(candidate):
                        continue
                    # One line per distinct leak: the same string survives in
                    # dozens of revisions and 68 repeats bury the signal.
                    findings.append(f"{path} {label}: {candidate}")
    return findings


def scan_messages(repo: Path) -> list[str]:
    findings: list[str] = []
    text = _git(repo, "log", "--all", "--format=%H%x09%B")
    for block in text.splitlines():
        if "\t" not in block:
            continue
        sha, message = block.split("\t", 1)
        for label, pattern in PATTERNS:
            for match in pattern.finditer(message):
                candidate = match.group(0)
                if _allowed(candidate):
                    continue
                findings.append(f"commit message {label}: {candidate}")
    return findings


def scan_authors(repo: Path) -> list[str]:
    findings: list[str] = []
    seen = set()
    for line in _git(repo, "log", "--all", "--format=%ae%x09%ce").splitlines():
        for address in line.split("\t"):
            if address in seen:
                continue
            seen.add(address)
            if "@users.noreply.github.com" in address or address.endswith(
                ("@local.invalid", "@localhost")
            ):
                continue
            findings.append(f"author identity is personal: {address}")
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", type=Path, default=Path("."))
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()
    repo = args.repo.resolve()
    if not (repo / ".git").exists():
        print(f"not a git repository: {repo}", file=sys.stderr)
        return 2
    revs = revisions(repo)
    if not revs:
        print("no history to check", file=sys.stderr)
        return 2
    raw = [*scan_blobs(repo, revs), *scan_messages(repo), *scan_authors(repo)]
    findings = list(dict.fromkeys(raw))
    if not findings:
        if not args.quiet:
            print(f"history clean: {len(revs)} revision(s), no personal data")
        return 0
    for finding in findings[:50]:
        print(finding, file=sys.stderr)
    if len(findings) > 50:
        print(f"... and {len(findings) - 50} more", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())