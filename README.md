# Lumos Network Mapper

Lumos is a terminal-based network mapper, built on the user's own installed copy of Nmap. It is intended to help authorized penetration testers, red/blue teams, and network engineers map and document networks. Version 0.1 is the database/schema skeleton; scanning, topology rendering, and reporting are not implemented yet.

## Authorized use

Use this tool only on systems and networks you own or are explicitly authorized to assess. You are responsible for confirming the scope and permissions before starting any scan.

## Requirements

- Python 3.10 or newer; runtime code uses only the Python standard library.
- The user's own Nmap installation will be required for scan features. Lumos does not bundle or download Nmap.
- Linux is the initial platform target. The v1 UI is intended for SSH/tmux-compatible terminals.

## Current skeleton quick start

From a checkout, the Phase 1 CLI can create and verify an engagement database:

```sh
PYTHONPATH=src python3 -m lumos db init ./engagement.sqlite --name "Example assessment"
PYTHONPATH=src python3 -m lumos db check ./engagement.sqlite
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Database creation refuses to overwrite an existing file and sets owner-only permissions. Do not commit engagement databases, raw scan XML, or generated reports.

## Nmap and data handling

Lumos invokes the Nmap executable selected from the user's `PATH`; it does not bundle Nmap or read/copy Nmap's data files. Nmap output and imported databases are untrusted input. Avoid storing credentials in notes or scan scripts. Protect engagement files with appropriate OS-level disk encryption and access controls.

## Development status

Phase 1 provides the merge-ready schema v1, forward-only migration entry point, database checks, synthetic XML fixtures, and a fake Nmap executable for offline tests. Later phases will add scan execution, XML parsing, scope enforcement, topology UI, merging, review, notes, and exports. Until implemented and tested, those features are not available.

## License

No license has been selected yet. No `LICENSE` file is included. Choose and review a license before the first public commit.
