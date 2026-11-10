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

Implemented: schema-v1 database creation and checks; scope rules; Nmap version discovery, safe argument-vector execution, streamed XML parsing and persistence; exact-hostname allowlisting before Nmap-based hostname resolution; scan audit/provenance and compressed raw XML evidence; bounded Nmap XML import; Markdown report; and a bounded, read-only map/host TUI. `lumos tui DATABASE` opens curses on a terminal and prints an ASCII snapshot when output is redirected. The TUI supports keyboard node navigation, search, refresh, resize, `NO_COLOR`, host-list view, and edge provenance details. While open, it detects committed database changes from concurrent scans and refreshes the map/status; scan batches become visible after their SQLite commit. The standalone `lumos interfaces` command reads local interface and route information from the installed Nmap's `--iflist` option and provides text or JSON output; it does not scan targets. The TUI does not launch scans yet. The scan command displays the final Nmap command before execution. User-specified Nmap `-oN` and `-oG` output files are retained alongside Lumos's XML stream. An `-oX` or `-oA` manual option conflicts with XML-on-stdout and is rejected with an explanation.

The TUI remains a prototype: it currently watches committed snapshots rather than displaying streamed Nmap stderr/progress; it does not yet persist `lumos interfaces` data on the root node, save positions, pan/zoom, support mouse interaction, or provide scan/review/notes panels. Map edges now use a tested 2-by-4 Unicode braille rasterizer when Unicode is available, with the existing ASCII line renderer as fallback; edge types retain distinct solid, parallel, dotted, and dashed patterns. The full phase still needs broader resize/color/SSH/tmux coverage and idle-CPU measurement. Merge, scan profiles/queue, comparisons, notes editor, manual topology editing, sanitization, synthetic demo generator, HTML/SVG/CSV/JSON exports, plugins, and performance benchmarks are not implemented. Do not treat Phase 3 as finished.

Nmap progress flags are included only when the installed executable advertises them in its help output. The installed Nmap build used during development did not advertise `--stats-every`, so periodic Nmap progress may be unavailable on that build. Traceroute topology must not be inferred from the current default connect scan; Nmap documents that traceroute is incompatible with `-sT`.

## Quick start

From a source checkout:

```sh
PYTHONPATH=src python3 -m lumos interfaces --json
PYTHONPATH=src python3 -m lumos db init ./engagement.sqlite --name "Example assessment"
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

Database creation refuses to overwrite an existing path and sets owner-only permissions. Report output is also created owner-only. Do not commit engagement databases, raw scan XML, or generated reports.

## Data handling and Nmap

Lumos invokes the Nmap executable selected from `PATH` with an argument list and no shell. It parses Nmap XML incrementally, keeps completed hosts when possible after truncated output, and caps imported XML size and nesting. Imported Nmap XML is retained in compressed form by default; pass `--no-evidence` to disable evidence retention for scans or imports. Nmap-supplied text is sanitized before terminal/report output.

The database records scan commands, Nmap version, timestamps, operator, interface, vantage point, scope override status, and exit state. Scope rules are engagement-wide; `--network` associates observations with a named network and does not narrow the scope rules. Exact-hostname allow rules are required before hostname preflight resolution.

## Development status and project hygiene

Phase 1 established the merge-ready schema, migration entry point, database validation, synthetic Nmap XML fixtures, and an offline fake Nmap executable. Phase 2 adds the headless scan/import/report path. CI and unit tests do not run scans or require network access. Python 3.10 and a real Nmap scan have not yet been verified in this environment.

No license has been selected and no `LICENSE` file is included. Select and review a license before public distribution. Nmap is a separate project and trademark; consult its current licensing and trademark terms before release.
