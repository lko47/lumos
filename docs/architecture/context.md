# Context

Shows the operator, the scanner host with the curses interface and CLI, the host's own Nmap binary, the engagement SQLite file, another engagement file used only as a merge source, and exported reports.
Leaves out every process, thread, table and HTTP-shaped integration inside the scanner host; there is no server, no telemetry and no bundled copy of Nmap.
Derived from `README.md`, `src/lumos/cli.py`, `src/lumos/services/actions.py` and `core/nmap/runner.py::find_nmap`.

```mermaid
flowchart TB
    operator(["Operator at a terminal"])
    subgraph host["Scanner host — runs as the invoking user"]
        tui["lumos.tui<br/>curses event loop"]
        cli["lumos.cli"]
        actions["lumos.services.actions"]
        scan["core.scanning.scan_database<br/>core.nmap.runner.find_nmap"]
        nmap["installed nmap<br/>(PATH or --nmap)"]
        db[("engagement.sqlite<br/>application_id 0x4C554D53, schema 3")]
    end
    other[("another engagement file<br/>same meta.engagement_uid")]
    reports["exported reports<br/>Markdown / SVG, mode 0600"]

    operator -->|"keys"| tui
    operator -->|"argv"| cli
    tui --> actions
    cli --> actions
    actions --> scan
    scan --> nmap
    nmap -->|"Nmap XML on stdout"| scan
    actions -->|"SQLite, WAL"| db
    other -->|"db merge: read-only, uid must match"| actions
    actions -->|"write_markdown_report<br/>write_svg_report"| reports
```
