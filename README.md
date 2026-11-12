# Lumos Network Mapper

Lumos is a terminal-first network mapper built on the user's own installed Nmap. It stores scan observations, scope, audit history, review flags, and notes in a portable SQLite engagement file. Use it only for systems and networks you own or are explicitly authorized to assess. Lumos is not affiliated with the Nmap Project and does not bundle Nmap.

The project name is provisional. No game assets, names, or layouts are used.

## Requirements and safety

- Python 3.10 or newer; runtime code uses only the standard library.
- Nmap installed separately and available on `PATH` (or supplied with `--nmap`). Lumos never downloads Nmap or reads its data files.
- Linux is the initial platform target. No Windows support is planned for version 1.
- The CLI runs as the invoking user. Nmap may need capabilities or elevated privileges for selected scan modes; never run the whole UI as root.
- Scan only authorized targets. Lumos checks targets against engagement-wide allow and exclude rules before starting Nmap. An out-of-scope override requires the exact displayed phrase and is recorded.
- Nmap XML and imported databases are untrusted input. Protect engagement files with OS permissions, access controls, and disk encryption. Do not store credentials in notes or scan scripts.

## Current status: Phase 3 in progress

Implemented: schema-v2 database creation, upgrade, and checks; scope rules; Nmap version discovery, safe argument-vector execution, streamed XML parsing and persistence; exact-hostname allowlisting before Nmap-based hostname resolution; scan audit/provenance and compressed raw XML evidence; bounded Nmap XML import; Markdown report; and a bounded, read-only map/host/scan TUI. `lumos tui DATABASE` opens curses on a terminal and prints an ASCII snapshot when output is redirected.

The TUI has three tabs (`m` map, `v` hosts, `s` scans, `Tab` cycles), a durable keyboard identity, a command palette (`:`), a help overlay (`?`), incremental search (`/`), and manual refresh (`r`). The map draws only stored `topology_edges` (Nmap-observed or explicitly marked inferred), using a tested 2-by-4 Unicode braille rasterizer with per-edge-type patterns and an ASCII line fallback (`LUMOS_ASCII=1` forces it). Node placement is a deterministic ring layout keyed on a blake2b hash of the node id, so new discoveries never reshuffle existing nodes; the viewport supports zoom (`+`/`-`), pan (`H`/`J`/`K`/`L`), and reset (`0`). The detail sidebar lists addresses, OS, open ports per node, hop distance, review flags, and — for the scanner root — any vantage interfaces saved by `lumos interfaces --save`. Edge selection shows provenance, confidence, and timestamps. The scans tab lists recent scans with status, host counts, elapsed time, and targets, read from a bounded projection of the scans table.

Colour is semantic rather than hard-coded: themes `aurora`, `ember`, and `matrix` degrade to 16-colour palettes, and `NO_COLOR` selects a monochrome theme that keeps hierarchy through weight and reverse video only. `LUMOS_THEME` selects the starting theme. While open, the TUI detects committed database changes from concurrent scans and refreshes the map/status; scan batches become visible after their SQLite commit. The standalone `lumos interfaces` command reads local interface and route information from the installed Nmap's `--iflist` option and provides text or JSON output; it does not scan targets. `lumos interfaces --save` records those interfaces on the engagement's vantage point. The TUI does not launch scans yet. The scan command displays the final Nmap command before execution. User-specified Nmap `-oN` and `-oG` output files are retained alongside Lumos's XML stream. An `-oX` or `-oA` manual option conflicts with XML-on-stdout and is rejected with an explanation.

The TUI remains a prototype: it watches committed snapshots rather than displaying streamed Nmap stderr/progress, and it does not yet save positions, support mouse interaction, edit topology, or provide review/notes panels. Idle CPU measured 0.02 s over a 5 s idle window (0.4% of one core) in a 110x32 PTY on Python 3.14.9; resize, colour, SSH, and tmux coverage and the Python 3.10 run are still outstanding. Merge, scan profiles/queue, comparisons, notes editor, manual topology editing, sanitization, synthetic demo generator, HTML/SVG/CSV/JSON exports, plugins, and performance benchmarks are not implemented. Do not treat Phase 3 as finished.

Nmap progress flags are included only when the installed executable advertises them in its help output. The installed Nmap build used during development did not advertise `--stats-every`, so periodic Nmap progress may be unavailable on that build. Traceroute topology must not be inferred from the current default connect scan; Nmap documents that traceroute is incompatible with `-sT`.

## Quick start

From a source checkout:

```sh
PYTHONPATH=src python3 -m lumos interfaces --json
PYTHONPATH=src python3 -m lumos db init ./engagement.sqlite --name "Example assessment"
PYTHONPATH=src python3 -m lumos interfaces ./engagement.sqlite --save
PYTHONPATH=src python3 -m lumos scope add ./engagement.sqlite 192.0.2.0/24 --network example --author analyst
PYTHONPATH=src python3 -m lumos scope show ./engagement.sqlite
PYTHONPATH=src python3 -m lumos scan ./engagement.sqlite 192.0.2.10 --network example
PYTHONPATH=src python3 -m lumos import ./engagement.sqlite ./saved-scan.xml --network example
PYTHONPATH=src python3 -m lumos report markdown ./engagement.sqlite ./assessment.md
PYTHONPATH=src python3 -m lumos db check ./engagement.sqlite
PYTHONPATH=src python3 -m lumos tui ./engagement.sqlite
```

`192.0.2.0/24` is documentation-only address space; replace it with an explicitly authorized target and scope. By default, the scan command displays its exact command and asks for interactive confirmation. In non-interactive use, `--yes` skips that prompt; review the target and options before using it in automation. For a target outside the allowlist, the CLI blocks the scan and prints the exact typed override phrase; use `--confirm-scope` only when authorized.

To run the offline test suite without network access or a real scan:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Database creation refuses to overwrite an existing path and sets owner-only permissions. Report output is also created owner-only. Do not commit engagement databases, raw scan XML, or generated reports. `lumos db upgrade DATABASE` applies forward-only migrations to an existing file in place; the database keeps `application_id` `0x4C554D53` ("LUMS") and `user_version` 3.

## Data handling and Nmap

Lumos invokes the Nmap executable selected from `PATH` with an argument list and no shell. It parses Nmap XML incrementally, keeps completed hosts when possible after truncated output, and caps imported XML size and nesting. Imported Nmap XML is retained in compressed form by default; pass `--no-evidence` to disable evidence retention for scans or imports. Nmap-supplied text is sanitized before terminal/report output.

The database records scan commands, Nmap version, timestamps, operator, interface, vantage point, scope override status, and exit state. Scope rules are engagement-wide; `--network` associates observations with a named network and does not narrow the scope rules. Exact-hostname allow rules are required before hostname preflight resolution.

## Merge identity and schema

The file format is designed for a read-only merge that does not duplicate rows:

- Row ids for networks, addresses, devices, vantage points, topology nodes and edges, tags, scope rules, and review items are UUIDv5 values derived from each row's natural key (`core/ids.py`). Re-importing the same scan or merging the same source twice therefore resolves to the same ids.
- The engagement itself is identified by `meta.engagement_uid`, derived once from the engagement name and creation timestamp. A merge is only accepted when the source uid matches; every incoming `engagement_id` is then rewritten to the local `engagement.id` while child ids stay unchanged. A different uid is a different engagement and is rejected, never silently rehomed.
- Devices are deliberately **not** keyed on address or hostname: the same host seen twice stays two devices with a duplicate proposal until a human decides.
- Schema 2 adds `meta` and `merge_log` (one row per merge attempt, with outcome `applied`, `rejected`, or `dry_run`), plus unique indexes on the natural keys of scope rules, review items, duplicate proposals, topology edges, vantage points, trace paths, script observations, and identity claims. Exact duplicates are collapsed to the earliest row when a v1 file is upgraded.
- `lumos db upgrade DATABASE` migrates an existing v1 file in place; `lumos db check DATABASE` verifies `application_id`, `user_version`, the table/view set, foreign keys, and integrity.

## Inferred links

Not every scan has traceroute data: unprivileged scans fall back to `connect()`
probes, which skip ARP, and Nmap's traceroute does not work with connect
scans. Lumos therefore derives a *likely* structure from facts it does store,
and marks every derived row so a guess never looks like a measurement.

Inputs are recorded per scan: the interface table (address, prefix, type) and
the routing table from `nmap --iflist`, captured automatically when a scan
starts, plus each host's status reason, reason TTL and MAC. `lumos db rebuild
DATABASE` re-derives everything from those facts; it also runs automatically
after a completed scan or import.

| Rule | Draws | Confidence |
| --- | --- | --- |
| `local_interface` | scanner root to a segment hub for one of its own connected networks | 1.0 |
| `on_link_arp` | hub to host, when the host answered ARP/ND and has a MAC | 0.95 |
| `on_link_address` | hub to host, addressing only | 0.70 |
| `gateway_on_link` | hub to the gateway (the scanned device, else a placeholder hop) | 0.90 |
| `routed_via_gateway` | gateway to a routed-subnet hub, then hub to host | 0.50 / 0.60 or 0.40 (assumed prefix) |
| `unknown_path` | root to a "path unknown" hub, then hub to host, when no interface or route data exists | 0.20 / 0.40 |

Hubs are broadcast domains or routed subnets, never devices, and are keyed on
the network row plus the CIDR, so two scanners in one network share a hub and
two different `10.0.0.0/24` networks never merge. An observed traceroute path
from the same vantage point always wins: that host gets no inferred link, but
keeps its zone membership. Many addresses answering ARP with one MAC are
treated as suspected proxy ARP: those links are downgraded to addressing
evidence and one review item names the MAC. Tunnel interfaces never supply ARP
evidence, and link-local IPv6 or host routes (`/32`, `/128`) never create a
segment hub.

Every derived edge stores its rule, rule version and the row ids it used in
`evidence_json`; `edge_decisions` records a user's `promoted` or `rejected`
choice and survives rebuilds and merges. Rows the rebuild does not regenerate
are deleted, but only when `derived = 1`.

Rendering uses the evidence class: solid for observed and local links, dense
dots for likely (>= 0.6), sparse dots for weak evidence, and a dashed style for
manual links. The map, the evidence panel, hub collapsing and SVG report output
for these classes are not implemented yet.

## Development status and project hygiene

Phase 1 established the merge-ready schema, migration entry point, database validation, synthetic Nmap XML fixtures, and an offline fake Nmap executable. Phase 2 adds the headless scan/import/report path. CI and unit tests do not run scans or require network access. Python 3.10 and a real Nmap scan have not yet been verified in this environment.

`bench/map_benchmark.py` builds synthetic 10k/100k-host engagements and reports load and frame timings; it is a development tool and needs no network or Nmap access. Results on this machine (Python 3.14.9, 8 CPUs) are recorded in the project plan rather than in CI.

No license has been selected and no `LICENSE` file is included. Select and review a license before public distribution. Nmap is a separate project and trademark; consult its current licensing and trademark terms before release.
