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

## Current status: MVP interface (v0.2)

Implemented: schema-v2 database creation, upgrade, and checks; scope rules; Nmap version discovery, safe argument-vector execution, streamed XML parsing and persistence; exact-hostname allowlisting before Nmap-based hostname resolution; scan audit/provenance and compressed raw XML evidence; bounded Nmap XML import; Markdown report; and a bounded, read-only map/host/scan TUI. Bare `lumos` opens the interface; `lumos DATABASE` opens that engagement, and the old `lumos tui DATABASE` still works. `LUMOS_DB` supplies a default database.

The interface is mouse-first as well as keyboard-first, and it moves: three slow dots travel outward along every link, coloured by how well the path is known: green measured (traceroute or a directly observed host), amber inferred with confidence, red weak inference or an unknown hop, cyan local interface; manual and imported links never move, and while motion is on the links themselves are drawn solid so the dots read as traffic rather than as a trail of static dots (`a` restores the dotted evidence styles) nodes that appear in a new snapshot blink in with a short ripple, and a liveness strip in the footer advances once a second from real event counts (`a` turns motion off, which is also what a screen reader or a `script(1)` capture wants). tabs, map nodes, hosts and scans table rows, footer hints, dialog fields and their Save/Cancel line are all clickable, the wheel zooms the map at the pointer and scrolls the lists, dragging the map pans it (arrow keys and HJKL pan too, `0` recentres), and every mouse action has a keyboard equivalent. The TUI has three tabs (`m` map, `v` hosts, `s` scans, `Tab` cycles), a durable keyboard identity, a command palette (`:`), a help overlay (`?`), incremental search (`/`), and manual refresh (`r`). The map draws only stored `topology_edges` (Nmap-observed or explicitly marked inferred), using a tested 2-by-4 Unicode braille rasterizer with per-edge-type patterns and an ASCII line fallback (`LUMOS_ASCII=1` forces it). Node placement is a deterministic ring layout keyed on a blake2b hash of the node id, so new discoveries never reshuffle existing nodes; the viewport supports zoom (`+`/`-`), pan (`H`/`J`/`K`/`L`), and reset (`0`). The detail sidebar lists addresses, OS, open ports per node, hop distance, review flags, and — for the scanner root — any vantage interfaces saved by `lumos interfaces --save`. Edge selection shows provenance, confidence, and timestamps. The scans tab lists recent scans with status, host counts, elapsed time, and targets, read from a bounded projection of the scans table.

Colour is semantic rather than hard-coded: themes `aurora`, `ember`, and `matrix` degrade to 16-colour palettes, and `NO_COLOR` selects a monochrome theme that keeps hierarchy through weight and reverse video only. `LUMOS_THEME` selects the starting theme. While open, the TUI detects committed database changes from concurrent scans and refreshes the map/status; scan batches become visible after their SQLite commit. The standalone `lumos interfaces` command reads local interface and route information from the installed Nmap's `--iflist` option and provides text or JSON output; it does not scan targets. `lumos interfaces --save` records those interfaces on the engagement's vantage point. The TUI launches scans from the `S` form (preset, targets, network, interface, evidence) after a review step that shows the exact argv and the scope verdict; progress streams in a panel from Nmap's `taskprogress` element and `Esc` twice cancels, keeping the hosts already written. Creating a database (`N`), editing scope (`P`), importing XML (`I`), writing reports (`R`), database checks/upgrade/rebuild/merge/interfaces (`T`), and an event log (`!`) are all reachable from the map, and each is also a command in the `:` palette. The CLI and the interface call the same functions in `services/actions.py`, so both front ends behave identically. The **scan** command displays the final Nmap command before execution. User-specified Nmap `-oN` and `-oG` output files are retained alongside Lumos's XML stream. An `-oX` or `-oA` manual option conflicts with XML-on-stdout and is rejected with an explanation.

The TUI remains a prototype: it watches committed snapshots and streams `<taskprogress>` updates, but it does not show Nmap stderr line by line, save node positions, edit topology, or provide review and notes panels. Mouse, keyboard and drag/zoom panning are all implemented. Idle CPU measured 0.02 s over a 5 s idle window (0.4% of one core) in a 110x32 PTY on Python 3.14.9; resize, colour, SSH, and tmux coverage and the Python 3.10 run are still outstanding. A scan queue and a notes editor, manual topology editing, HTML/CSV/JSON exports, plugins, scheduling, and a config file beyond `LUMOS_DB` are not implemented. Four engines can enumerate: **Nmap** (services, OS, traceroute), **masscan** (XML import or a direct run), **naabu** (JSON lines) and **rustscan** (greppable text). Each runs through the same scope guard, audit trail and database; naabu and rustscan output is normalised into Nmap-shaped XML rather than teaching the schema three formats, so there is one evidence path, and `<nmaprun scanner=...>` records which tool produced the rows. `,` opens the enumeration settings page, a checkbox per engine with its resolved path or `not installed`; a disabled engine is refused before its binary runs, and the scan dialog only offers engines that are both installed and switched on. masscan needs raw-socket privileges, and neither masscan, naabu nor rustscan reports services or OS details. Ping discovery (`-sn`) is available as a preset and as a manual option: it records hosts and nothing else, which is the "who is on my network" question, and it refuses to combine with any port or version probe. Targets can come from a file with `--target-file FILE` (blank lines and `#` comments ignored, duplicates collapsed, 4096 entries max); Nmap's own `-iL` is deliberately refused, because Lumos reads the list itself so every line passes the same scope check as a typed target — a file containing one out-of-scope address blocks the whole scan with the usual typed phrase. `-oX`/`-oA` stay refused in manual options: they would write a second XML file next to the stream Lumos parses, so `-oN`/`-oG` are the supported additional outputs.

Nmap progress flags are enabled for builds that support `--stats-every` (7.60 or newer, or when the flag appears in the help text) and are read from the `<taskprogress>` elements Nmap writes into the XML stream; on older builds the panel shows elapsed time and a plain working indicator instead. Traceroute topology must not be inferred from the current default connect scan; Nmap documents that traceroute is incompatible with `-sT`.

### Keys worth knowing

| Key | Action |
| --- | --- |
| `m` `v` `s` / `Tab` | map, hosts, scans |
| click / `Enter` | select a node, edge, row or field |
| `o` / `O` | toggle the selected hub / collapse every hub |
| `[ set start ]` `[ set end ]` | click the sidebar buttons to mark a path |
| `b` / `y` / `f` | note / tags / pin the selected node |
| `z` | review queue: pick an item, then confirm, ignore, flag or mark out of scope |
| `a` | motion on/off (dots, ripples, solid links) |
| `+` `-` `0` | zoom in, zoom out, recentre |
| arrows, `HJKL`, drag, wheel | pan, and zoom at the pointer |
| `S` | scan form (preset, engine, targets, network) |
| `w` | add another engagement to the view |
| `,` | enumeration settings (engine checkboxes) |
| `N` `P` `I` `R` `T` `!` | new engagement, scope, import XML, report, database tools, event log |
| `?` `:` `/` | help, command palette, search |
| `lumos note DB "text" --node ID` | attach a note to a node (`--list` to read them back; the sidebar shows the newest) |
| `lumos tag DB dmz --node ID` | tag a node (`--list`, `--remove`) |
| `lumos queue DB --add --network N TARGET` | queue scans (`--list`, `--remove ID`, `--clear`, `--run`) |
| `lumos review DB [--decide ID --set confirmed]` | review queue and decisions |
| `lumos scan DB --target-file FILE` | scope-checked targets from a file (`-sn` preset for discovery) |
| `lumos report json\|csv\|html DB OUT` | machine-readable exports (owner-only files) |
| `lumos compare DB` | diff the last two completed scans (`--from`/`--to` take an id or a unique prefix, `--list` shows them) |

### Engagements, hubs and paths

Several engagement files can be opened in one view (`w`): each file keeps its own cluster, node ids are prefixed per member, roots are labelled `[engagement] host`, and any host whose address appears in more than one file is joined to its twin by a `═` bridge in the `shared` evidence class. Files are opened `mode=ro` and are never rewritten, so the imported engagement stays exactly as it was; the caps are eight members and 128 bridges.

Hubs are **collapsed by default**, so the map opens as a view of hops rather than a wall of hosts. The SELECTED panel carries `[ expand members ]` / `[ collapse members ]` for the chosen hub (`o` toggles the selected hub, `O` collapses every hub), which is also how a NAT'd inner network folds into the single straight link between its parent and the hub.

`[ set start ]` and `[ set end ]` mark two nodes and highlight the shortest path between them: path nodes carry a `▶` marker, the links on the path take the path style, and the hop count appears in the panel and the status line. The path is a breadth-first search over the edges the current view actually draws, so collapsing a hub really does change the route, and an unreachable pair reports that instead of drawing a line.

## Quick start

```sh
pipx install .        # or: python3 -m pip install --user .
lumos                 # opens the interface; N creates the first engagement
lumos engagement.sqlite
```

Everything below is also reachable from the interface; the CLI remains for
scripting and for headless machines. From a source checkout, prefix each with
`PYTHONPATH=src python3 -m`:

```sh
lumos interfaces --json
lumos db init ./engagement.sqlite --name "Example assessment"
lumos interfaces ./engagement.sqlite --save
lumos scope add ./engagement.sqlite 192.0.2.0/24 --network example --author analyst
lumos scope show ./engagement.sqlite
lumos scan ./engagement.sqlite 192.0.2.10 --network example
lumos import ./engagement.sqlite ./saved-scan.xml --network example
lumos report markdown ./engagement.sqlite ./assessment.md
lumos db merge ./engagement.sqlite ./copy.sqlite --dry-run
lumos db check ./engagement.sqlite
```

Interface keys: `N` new engagement, `P` scope rules, `S` scan, `I` import XML,
`R` report, `T` tools (check, upgrade, rebuild, merge, interfaces), `!` event
log, `:` palette, `?` help. Existing map keys (`m`/`v`/`s`, `o`/`O`, `i`,
`p`/`x`, `/`, `t`, `+`/`-`, `H J K L`, `0`, `q`) are unchanged.

`192.0.2.0/24` is documentation-only address space; replace it with an explicitly authorized target and scope. By default, the scan command displays its exact command and asks for interactive confirmation. In non-interactive use, `--yes` skips that prompt; review the target and options before using it in automation. For a target outside the allowlist the scan is blocked: the TUI asks you to tick an acknowledgement and press a red Confirm button, and the CLI prints the exact override phrase to pass with `--confirm-scope`. Both are recorded in the audit log.

To run the offline test suite without network access or a real scan:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Every fixture and test uses reserved address space, never a real network: RFC 5737
documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), RFC 3849
`2001:db8::/32`, RFC 2544 benchmarking space (`198.18.0.0/15`) for the synthetic
scale benchmark, and locally administered MACs (`02:00:…`). `10.0.0.0/24` appears in
prose only, as the textbook example of two private networks that share a CIDR. No
engagement database, scan XML, or report is committed.

Database creation refuses to overwrite an existing path and sets owner-only permissions. Report output is also created owner-only. Do not commit engagement databases, raw scan XML, or generated reports: `.gitignore` excludes them, and `tests/test_repo_hygiene.py` fails the suite (and CI) if one is ever tracked. Committed Nmap XML is limited to synthetic fixtures under `tests/fixtures/nmap/`. `lumos db upgrade DATABASE` applies forward-only migrations to an existing file in place; the database keeps `application_id` `0x4C554D53` ("LUMS") and `user_version` 3.

## Data handling and Nmap

Lumos invokes the Nmap executable selected from `PATH` with an argument list and no shell. It parses Nmap XML incrementally, keeps completed hosts when possible after truncated output, and caps imported XML size and nesting. Imported Nmap XML is retained in compressed form by default; pass `--no-evidence` to disable evidence retention for scans or imports. Nmap-supplied text is sanitized before terminal/report output.

The database records scan commands, Nmap version, timestamps, operator, interface, vantage point, scope override status, and exit state. A scan whose process died without finishing (crash, killed terminal) is closed as `failed` and logged as `scan_interrupted` the next time the engagement is opened or scanned, so the interface stops reporting a scan that no longer exists. Scope rules are engagement-wide; `--network` associates observations with a named network and does not narrow the scope rules. Exact-hostname allow rules are required before hostname preflight resolution.

## Merge identity and schema

The file format is designed for a read-only merge that does not duplicate rows:

- Row ids for networks, addresses, devices, vantage points, topology nodes and edges, tags, scope rules, and review items are UUIDv5 values derived from each row's natural key (`core/ids.py`). Re-importing the same scan or merging the same source twice therefore resolves to the same ids.
- The engagement itself is identified by `meta.engagement_uid`, derived once from the engagement name and creation timestamp. A merge is only accepted when the source uid matches; every incoming `engagement_id` is then rewritten to the local `engagement.id` while child ids stay unchanged. A different uid is a different engagement and is rejected, never silently rehomed.
- Devices are deliberately **not** keyed on address or hostname: the same host seen twice stays two devices with a duplicate proposal until a human decides.
- Schema 2 adds `meta` and `merge_log` (one row per merge attempt, with outcome `applied`, `rejected`, or `dry_run`), plus unique indexes on the natural keys of scope rules, review items, duplicate proposals, topology edges, vantage points, trace paths, script observations, and identity claims. Exact duplicates are collapsed to the earliest row when a v1 file is upgraded.
- `lumos db merge TARGET SOURCE` copies another copy of the same engagement into the target. A source with a different `engagement_uid` is refused and recorded in `merge_log` with outcome `rejected`; a matching one is copied table by table with `INSERT OR IGNORE`, so re-running the merge adds nothing. `--dry-run` does the inserts inside a savepoint, reports what would be new, then rolls them back and logs `dry_run`. After a merge the inference engine re-runs, so rejected links stay rejected and promoted ones stay manual.
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
segment hub. Virtual bridges (`docker0`, `br-`, `virbr`, `veth*`) are marked
`virtual` and hidden until a scan puts members on them. A host's status TTL is
shown in the details panel as an "about N hops" hint (never drawn), and rings
are labelled *depth*, not hops.

Every derived edge stores its rule, rule version and the row ids it used in
`evidence_json`; `edge_decisions` records a user's `promoted` or `rejected`
choice and survives rebuilds and merges. Rows the rebuild does not regenerate
are deleted, but only when `derived = 1`.

Rendering uses the evidence class: solid for observed and local links, dense
dots for likely (>= 0.6), sparse dots for weak evidence, and a dashed style for
manual links. Hubs draw as one node with their member count (`◇ 10.0.0.0/24 ·
212`), assumed hubs keep the `~`, gateway placeholders draw hollow, and the
status bar carries a one-line legend that degrades to ASCII.

A hub with more than 50 members collapses: its member nodes and links are not
selected at all, so a 100,000-host engagement of 400 `/24` networks opens as 401
nodes and draws a frame in ~28 ms (benchmark below).

Selecting a link explains it: the sidebar shows the rule, and a plain sentence
such as "Inferred by on_link_arp: 198.51.100.14 is inside 198.51.100.0/24 on eth0
and answered ARP. Confidence 0.95." On an inferred link `p` promotes it to a
manual link (recorded with the author) and `x` rejects it, each after a second
press; both choices go to `edge_decisions` and survive rebuilds. `i` hides or
shows inferred links.

A collapsed hub expands on request: select it and press `o` (`O` collapses all).
Expansion re-runs the same bounded query with that one hub's members included,
and `load_hub_members()` pages a hub's member list (label, addresses, node id)
without materialising the network, so a /16 with 60,000 hosts stays openable.

Reports tell the same truth as the map. `lumos report markdown` lists inferred
links in their own table with rule and confidence and states that they were not
measured; `lumos report svg DATABASE OUT.svg` draws them dotted (three-on/two-off
for likely, one-on/five-off for weak) while measured and local links stay solid,
labels hubs with their CIDR and member count, and repeats the caveat in the
image and its description.

## Queueing scans

`lumos queue` records scans to run later, in the order given, and `--run` executes them one at a time through the same scope-checked path as a typed scan.

A queued job is an intention, not a measurement, so it lives in `<database>.queue.json` beside the database (owner-only, written through a temporary file) rather than in a table: no schema change, and a queue that never ran leaves no trace in the evidence. The file is treated as hostile on load - every field re-validated and sanitised, an unknown engine falls back to `nmap`, 32 jobs and 512 targets per job, and a file that cannot be understood is an error sentence rather than a silently empty queue.

A failure stops the run and keeps the rest of the queue: the next job may have been queued *because* of what the failed one would have found.

## History hygiene

`tests/test_repo_hygiene.py` fails the suite on personal data in the files on disk; `python3 scripts/check_history_pii.py` walks **every revision, every commit message and every author identity**, because a file sanitised today can still be reachable through an earlier commit. It is run by the test suite and belongs in a pre-release pass.

The history has been rewritten once for this reason (`git filter-repo`, force-push, tag re-pointed): real subnets became documentation ranges, `/home/<user>` paths became `/home/user`, a host label became `scanner-host`, and the author identity became a GitHub noreply address. Old commits that GitHub still holds are no longer referenced by any branch or tag.

## Development status and project hygiene

Phase 1 established the merge-ready schema, migration entry point, database validation, synthetic Nmap XML fixtures, and an offline fake Nmap executable. Phase 2 adds the headless scan/import/report path. CI and unit tests do not run scans or require network access. Python 3.10 and a real Nmap scan have not yet been verified in this environment.

`bench/map_benchmark.py` builds synthetic 10k/100k-host engagements and reports load and frame timings; it is a development tool and needs no network or Nmap access. Results on this machine (Python 3.14.9, 8 CPUs) are recorded in the project plan rather than in CI.

Coding standard: the mechanical subset of the JSF-AV C++ rules is enforced by `python3 scripts/check_standards.py` with a shrink-only baseline, and every deviation is recorded in [`docs/standards/JSF-AV-ALIGNMENT.md`](docs/standards/JSF-AV-ALIGNMENT.md).

Architecture diagrams — context, layers, scan and merge sequences, threads, the
schema split into four ER diagrams, the inference rules and the module import
graph — live in [`docs/architecture/README.md`](docs/architecture/README.md).

What this tool is checked against, what the checks actually enforce, and which
claims are *not* verified: [`docs/SECURITY-COMPLIANCE.md`](docs/SECURITY-COMPLIANCE.md)
(JSF-AV ratchet, OWASP Top 10 mapping, MITRE ATT&CK technique mapping, privacy
guards).
The ER and module diagrams are generated by `scripts/gen_erd.py` and
`scripts/gen_modules.py`; `tests/test_architecture.py` fails when a committed
copy is stale or when `core` imports `tui`, `cli` or `plugins`.

No license has been selected and no `LICENSE` file is included. Select and review a license before public distribution. Nmap is a separate project and trademark; consult its current licensing and trademark terms before release.
