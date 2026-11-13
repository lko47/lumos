# Merge sequence

Shows one `lumos db merge` from the command or the TUI tools menu through source validation, the engagement-uid check, the read-only attach and the row-by-row copy, ending in `merge_log` and a fresh inference rebuild.
Leaves out the per-table row conflict rules (there are none beyond `INSERT OR IGNORE`), the `raw_scan_evidence` blob handling, and the exact table order inside `TABLES`.
Derived from `cli.py` (`db merge`), `tui/flows.py::_flow_merge`, `services/actions.py::merge` and `core/merge.py`.

```mermaid
sequenceDiagram
    actor Operator
    participant Front as lumos.cli / lumos.tui
    participant Actions as services.actions
    participant Merge as core.merge
    participant Target as target engagement
    participant Source as source engagement (ro)
    participant Rebuild as core.inference

    Operator->>Front: db merge TARGET SOURCE [--dry-run]
    Front->>Actions: merge(target, source, dry_run)
    Actions->>Merge: merge_engagement(target, source)
    Merge->>Target: open_database(readonly=False)
    Merge->>Source: sqlite3.connect(mode=ro), trusted_schema=OFF
    Merge->>Merge: _source_schema_problem(source, target)
    alt application_id, user_version, tables, views or columns differ
        Merge->>Target: _log(outcome='rejected', reason)
        Merge-->>Actions: raise MergeError
    end
    Merge->>Source: ids.read_engagement_uid()
    Merge->>Merge: compare with ids.ensure_engagement_uid(target)
    alt uids differ
        Merge->>Target: _log(outcome='rejected')
        Merge-->>Actions: raise MergeError (different engagement)
    end
    Merge->>Target: SAVEPOINT dry_run (dry-run only)
    Merge->>Source: SELECT rows per table in TABLES order
    Merge->>Target: _copy_rows: INSERT OR IGNORE, CHUNK=2000,<br/>engagement_id rewritten
    alt dry run
        Merge->>Target: ROLLBACK TO dry_run; _log(outcome='dry_run')
        Merge-->>Actions: MergeStats(applied=False)
    end
    Merge->>Target: _log(outcome='applied', stats_json)
    Merge->>Rebuild: rebuild_inferred(target)
    Rebuild->>Target: hubs, edges, memberships
    Merge-->>Actions: MergeStats(applied=True, rows)
    Actions-->>Front: "merged: <table> <n>, …"
    Front-->>Operator: counts per table
```
