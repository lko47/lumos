# Threads and ownership

Shows the six threads, the objects each owns and the queues between them, including which threads hold a SQLite connection.
Leaves out the CLI path (it runs `scan_database` on the main thread and has no curses loop) and the exact batch sizes and timeouts.
Derived from `tui/app.py::_run_event_loop`, `tui/flows.py::run_task`, `services/actions.py::ScanJob`, `core/nmap/runner.py::run_nmap`, `core/scan_store.py::ScanWriter` and `services/map_view.py::MapSnapshotWatcher`.

```mermaid
flowchart TB
    subgraph ui["main thread — tui.app._run_event_loop"]
        W["curses window, ViewState<br/>no connection after F4"]
    end
    subgraph task["lumos-task — flows.run_task"]
        T["one action at a time:<br/>import, merge, rebuild, report, check"]
    end
    subgraph scan["lumos-scan — actions.ScanJob"]
        S["scan_database<br/>cancel_event, events queue"]
    end
    subgraph reader["lumos-nmap-reader — core.nmap.runner"]
        R["selectors on stdout/stderr<br/>sha256 digest, gzip evidence"]
    end
    subgraph writer["lumos-db-writer — core.scan_store"]
        DBW["write connection<br/>queue maxsize 128, batch 50"]
    end
    subgraph watch["lumos-map-watcher — services.map_view"]
        WAT["read-only connection<br/>PRAGMA data_version"]
        Q["snapshot queue maxsize 1"]
    end
    DB[("engagement.sqlite")]

    ui -->|"start / cancel"| scan
    scan --> reader
    reader -->|"submit_host"| writer
    ui -->|"run_task"| task
    watch --> Q -->|"take_latest"| ui
    writer --> DB
    watch --> DB
    task --> DB
```
