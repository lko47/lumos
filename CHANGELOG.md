# Changelog

## 0.2.0 - MVP interface

Bare `lumos` now opens the terminal interface, and every headless verb is
reachable from inside it. No schema, inference or visual changes.

### Added

- `lumos` with no arguments opens the map for the database in `LUMOS_DB`, or a
  start screen listing recent engagements when there is none. `lumos PATH`
  opens that engagement directly; `lumos tui PATH` still works.
- A curses-free `services/actions.py` layer. The CLI and the interface call the
  same functions, so their behaviour cannot drift.
- Interface flows: `N` new engagement, `P` scope rules, `S` scan with a review
  step and live progress, `I` import XML, `R` report, `T` tools (check,
  upgrade, rebuild, merge with dry-run preview, save interfaces), `!` event log.
- Every flow is also a `:` palette command.
- Scans cancel with `Esc` (SIGINT to Nmap, completed hosts retained).
- Recent engagements are kept in `$XDG_STATE_HOME/lumos/state.json`, never in
  the engagement database.

### Changed

- `lumos db init` prints the created path; the engagement id is available from
  `db check`.
- Import and scan previews create the named network if it does not exist, so
  the interface does not dead-end on a fresh database.
- Scan presets are `connect` (`-sT`), `service` (`-sV --top-ports 100`), `udp`
  (`-sU --top-ports 50`) and `custom`, matching the modes the runner accepts.

### Fixed

- Cancelling a scan no longer depends on raising `KeyboardInterrupt` inside a
  worker thread.
