# Security and compliance posture

This document states what Lumos is checked against, what the checks actually
enforce, and where the gaps are. It is written for the person who has to defend
using this tool on a real engagement — an auditor, a client, or a future
maintainer who needs to know which claims are backed by a test.

Three claims in this document are about *readings*, not certification: the JSF-AV
section adapts an avionics C++ standard to a different language and discipline,
the OWASP section is a mapping of one local CLI onto categories written for web
services, and the ATT&CK section lists the techniques Lumos *output* documents
rather than techniques it performs. Read them as design arguments with evidence,
and challenge any row whose evidence column does not convince you.

Run everything below with:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests
python3 scripts/check_standards.py
```

## JSF-AV (Joint Strike Fighter Air Vehicle C++ coding standard, adapted)

Lumos is Python, so the C++-specific rules (name mangling, header guards) do
not apply. The portable subset is enforced mechanically:

| Concern | Rule, adapted | Enforcement |
|---|---|---|
| Function size | AV 1 (≤200 lines) | `scripts/check_standards.py`; the ratchet fails on any new breach |
| Parameters | AV 110 (≤7) | same checker — three features in this project were reshaped (`EngineOptions`, `EngineRequest`, rect tuples) rather than baseline-logged |
| Magic numbers | AV 151 | named constants: `MAX_MEMBERS`, `MAX_BRIDGES`, `ENGINE_TIMEOUT_SECONDS`, `FLOW_PERIOD_SECONDS` |
| Global data | AV 207 | immutable module constants only (`ENGINES`, `SCHEMA_VERSION`) |
| Dead / commented-out code | AV 122, 127 | `vulture --min-confidence 80` is clean; no TODO/FIXME in `src/` |
| Exceptions | AV 208 (no exceptions in C++) | inverted: Python raises typed errors (`MergeError`, `EngineScanError`, `NmapXmlError`) and the UI turns them into sentences |

The ratchet is the important part: `.av-baseline` records 100 accepted
deviations, and `tests/test_standards.py::test_baseline_only_shrinks` fails if
that number grows. New code cannot buy compliance by adding debt.

**Known debt:** 100 accepted deviations remain (long SQL literals, a few
pre-existing complex functions). They are grandfathered, not fixed.

## OWASP Top 10 (2021), as it applies to a local offensive CLI

| Category | Position | Evidence |
|---|---|---|
| A01 Broken access control | Single-user local tool; there is no multi-tenant boundary to break. The meaningful control is **engagement scope**: `is_target_in_scope` runs before any packet, and the CLI/TUI refuse out-of-scope targets | `core/scope.py`, `core/engine_scan.py::check_engine_target`, `tests/test_engine_scan.py::test_out_of_scope_target_never_reaches_the_binary` |
| A02 Cryptographic failures | Nothing secret is stored. Evidence XML is compressed and hashed (SHA-256) for integrity, not encrypted | `core/xml_import.py::_compress_file` |
| A03 Injection | SQL is parameterised. Table/schema names are the one place a name is interpolated, and `_identifier()` now rejects anything that is not an identifier before it reaches SQL. XML parsing forbids DTDs and entity declarations outright (XXE). No shell is ever used: every command is an argument list | `core/merge.py::_identifier`, `core/nmap/xml_stream.py` ("DTD or entity declaration is forbidden"), `tests/fixtures/nmap/hostile-dtd.xml` |
| A04 Insecure design | Provenance over convenience: devices are never auto-merged by address, inferred links are visually distinct, and "unknown" is a state rather than a guess | `core/evidence.py`, `services/map_view.py::collapse_duplicates` (display-only fold) |
| A05 Security misconfiguration | A corrupt settings or state file falls back to a permissive-but-safe default instead of blocking an assessment; engagement databases are opened `mode=ro` for reads | `core/engines.py::load_enabled`, `services/workspace.py::engagement_name` |
| A06 Vulnerable components | Zero runtime dependencies — standard library only. The supply-chain surface is the Python install itself | `pyproject.toml` |
| A07 Auth failures | Not applicable: no accounts, no network service, no stored credentials | — |
| A08 Integrity failures | Every scan row records the exact and redacted argv, the tool version and the exit code; merges append a `merge_log` row; evidence keeps a SHA-256 | `core/schema.py`, `core/merge.py` |
| A09 Logging failures | Audit rows record what ran, when, by whom and against what. Scan labels and targets pass through `sanitize_text`, so a hostile hostname cannot inject terminal escapes into the UI | `core/text.py`, `scripts/review/hostile-escapes.xml` |
| A10 SSRF | No server-side fetching. Every network action targets an operator-supplied, scope-checked address | `core/scope.py` |

**Known gaps:** the settings file is plain JSON with no integrity check (it is
a preference, not a control); the TUI cannot cancel a running masscan/naabu
subprocess, only detach from its panel.

## MITRE ATT&CK — what this tool maps to

Lumos is an authorised-assessment tool. The techniques below are the ones its
output *documents*, which is what makes the resulting report legible to a
defensive team.

| Technique | ID | Where |
|---|---|---|
| Active Scanning: Scanning IP Blocks | T1595.001 | `nmap`/`masscan`/`naabu`/`rustscan` runs, one scan row per target |
| Active Scanning: Vulnerability Scanning | T1595.002 | Nmap service detection (`-sV`) presets |
| Network Service Discovery | T1046 | `port_observations` — protocol, port, state, service, product, version |
| Remote System Discovery | T1018 | `host_observations` per scan, with discovery method |
| System Network Connections Discovery | T1049 | **partial**: the traceroute/TTL hop chain plus the local vantage interfaces; the passive `/proc/net/tcp` inbound view is not built yet |
| Gather Victim Network Information | T1590 | Inferred topology, zones, gateway placement, `vantage_interfaces` |
| Gather Victim Host Information: Software | T1592.002 | OS match and service/product/version evidence |

Deliberately **not** implemented: exploitation, credential access, lateral
movement. An adjacency claim in Lumos is never a claim of access.

## Privacy: nothing personal goes public

The repository is public, so the suite enforces that no engagement data or
personal identifier can be committed:

- `tests/test_repo_hygiene.py` fails if a tracked file contains an engagement
  database, a private-range **host** address, or a `/home/<user>` path;
- fixtures use documentation ranges (RFC 5737 / RFC 3849) and
  locally-administered MACs only;
- engagement databases, XML exports and reports are git-ignored.

**Known gap:** earlier commits in the public history still contain lab subnets
(sanitised at HEAD, retrievable via `git log -p`). Removing them requires a
history rewrite and has not been done.

## Verification status

| Claim | Verified how |
|---|---|
| 384 tests pass | full suite, offline, no network |
| No new JSF-AV debt | ratchet + `tests/test_standards.py` |
| No shell execution | `subprocess.run(..., shell=False)` with list argv; `test_engine_scan.py` asserts the argument list |
| Out-of-scope targets never reach a binary | fake masscan writes a marker file; the test asserts it is absent |
| masscan reports import | fake binary emitting real masscan XML, end to end |
| Workspace never writes | files opened `mode=ro`; PTY run confirmed byte-identical after loading |
| Path highlighting is real | BFS over stored edges; PTY run produced "path: 2 hop(s)" |

**Not verified:** naabu and rustscan against the real binaries (not installed on
the development machine), masscan's privileged raw-socket path, and any Windows
or macOS behaviour.