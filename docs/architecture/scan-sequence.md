# Scan sequence

Shows one scan from the `S` form or `lumos scan` through `actions`, the scope guard, the Nmap runner and the XML parser, into the writer thread and SQLite, then the inference rebuild and the watcher back to the map.
Leaves out the form's field validation, the `--iflist` capture and import/hostname-preflight paths, and the CLI's interactive confirmation prompt.
Derived from `tui/flows.py::flow_scan`, `services/actions.py::ScanJob`, `core/scanning.py::scan_database`, `core/nmap/runner.py::run_nmap` and `core/scan_store.py::ScanWriter`.

```mermaid
sequenceDiagram
    actor Operator
    participant TUI as lumos.tui
    participant Actions as services.actions
    participant Scan as core.scanning
    participant Scope as core.scope
    participant Runner as core.nmap.runner
    participant Nmap as installed nmap
    participant XML as core.nmap.xml_stream
    participant Writer as core.scan_store.ScanWriter
    participant DB as SQLite
    participant Rebuild as core.inference
    participant Watch as services.map_view

    Operator->>TUI: S form (targets, preset, evidence)
    TUI->>Actions: preview_scan(database, targets, preset)
    Actions->>Scope: is_target_in_scope(target, rules)
    Scope-->>Actions: allowed / outside + phrase
    TUI->>Actions: ScanJob(...).start()
    Note over Actions: thread lumos-scan
    Actions->>Scan: scan_database(database, network, targets, options)
    Scan->>Scope: _check_target_scope(targets, rules)
    alt out of scope, no typed phrase
        Scan-->>Actions: ScopeConfirmationRequired
        Actions-->>TUI: done: blocked
    end
    Scan->>Runner: find_nmap / inspect_nmap / build_nmap_argv
    Scan->>Writer: ScanWriter(database, context)
    Scan->>Runner: run_nmap(argv, on_host=writer.submit_host)
    Note over Runner: thread lumos-nmap-reader
    Runner->>Nmap: Popen(argv, shell=False)
    Nmap-->>Runner: XML on stdout, text on stderr
    Runner->>XML: parse_nmap_xml(chunks)
    XML-->>Writer: HostRecord (queue maxsize 128)
    Note over Writer: thread lumos-db-writer
    Writer->>DB: batched INSERTs + commit
    Runner-->>Scan: NmapRunResult
    Scan->>Writer: finish(status, evidence)
    Scan->>Rebuild: rebuild_inferred(database)
    Rebuild->>DB: zones, topology_edges, memberships
    Watch->>DB: PRAGMA data_version
    Watch-->>TUI: MapSnapshot (queue maxsize 1)
    TUI-->>Operator: map redraw + footer status
```
