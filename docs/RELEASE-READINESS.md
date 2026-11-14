# Release readiness — 0.2.0

What has been checked, how, and what has not. If a row says "not verified", that
is the current state, not a to-do that has been quietly completed.

## Gates that run on every push

| Gate | Command | State |
| --- | --- | --- |
| Test suite | `PYTHONPATH=src python3 -W error -m unittest discover -s tests` | **522 tests, green** |
| Standards ratchet | `python3 scripts/check_standards.py` | exit 0, no new violations |
| Architecture diagram | `python3 scripts/gen_modules.py --check` | current |
| History hygiene | `python3 scripts/check_history_pii.py` | every revision clean |
| CI | `.github/workflows/tests.yml` | all four gates, Python 3.10 and 3.14 |

## Packaging

| Item | State |
| --- | --- |
| Licence | Apache-2.0 (`LICENSE`), declared in `pyproject.toml`, attribution in `NOTICE` |
| `pipx install .` / `uv tool install .` | works; pyproject with no runtime dependencies |
| zipapp | `python3 scripts/build_zipapp.py` → `dist/lumos.pyz`, ~186 KiB, runs `--version`, `demo` and `report` on a clean interpreter |
| Checksums | `dist/SHA256SUMS` written by the same script |
| Man page | `docs/man/lumos.1`, renders under `groff -man -ww` with no warnings; a test fails if a command is missing from it |
| Plugin examples | `examples/plugins/` — an exporter and a theme, both loaded and run in tests |

## Verified behaviour, with how it was verified

| Claim | Evidence |
| --- | --- |
| Sanitised export carries no original value | export of a real engagement rewritten in 162 fields plus 30 evidence values; a byte scan for every original finds none; source sha256 unchanged |
| Pseudonyms are stable and unique | two exports of the same engagement agree; a collision probes to the next value; tested |
| The demo is generated data | every address in a documentation range, every hostname `.example`, every MAC `02:00:`; asserted by test |
| Inferred is never drawn as measured | edge vocabulary in DOT, Mermaid, SVG, Markdown and the map; test asserts bold/dashed/solid mapping |
| Manual claims survive rebuilds | `rebuild_inferred` after adding a manual node and link; asserted by test |
| Identity is never auto-merged | duplicate proposals recorded, merged only on an explicit decision; asserted by test |
| Plugin failures are contained | a plugin that raises, one with a wrong API version and one with a bad name are refused with one sentence while a valid plugin loads |
| Keyboard flows are reachable | `d` (duplicates), `u` (manual node) and `t` (plugin theme) checked in a 110×32 PTY |
| The man page matches the program | test compares `cli.SUBCOMMANDS` against the page |

## Measured, with limits stated

`docs/BENCHMARKS.md` records medians for: demo generation 100.7 ms, map snapshot
2.8 ms, plain-text render 2.9 ms, JSON report 6.7 ms, DOT 1.7 ms, SVG 1.2 ms,
Markdown 4.6 ms, merge 10.9 ms, peak map memory 43 KiB.

**Not measured:** interactive frame latency (terminal I/O and the animation tick
are outside the harness), and any engagement larger than the 11-host demo. No
scale number is claimed.

## Not done

| Item | Why |
| --- | --- |
| README screenshots | no terminal rasteriser is available in this environment; the demo database that would feed them exists (`lumos demo`) |
| ~~Large-engagement scale test~~ | **measured**: `docs/BENCHMARKS.md` has 10,000 and 100,000-host runs from `bench/map_benchmark.py` (frame 16.9 ms and `rebuild_inferred` 18 s at 100k) |
| Privilege elevation | `-sS`/`-sU` require Lumos itself to hold the capability; there is no setuid or polkit helper, by design |
| Windows support | terminal interface targets POSIX; not attempted |
| NSE script browser | script output is stored and displayed, but there is no per-script explorer |
| Real masscan/naabu/rustscan runs | their parsers replay recorded fixtures only; no real binary has ever been run through Lumos |
| Git history object purge | old revisions are unreachable by ref, but only a repository reset or a GitHub support request removes them from the server's cache |

## Refusals worth knowing

- `-oA`, `-oX`, `-oN`, `-oG`, `-iL`, `--script` are refused everywhere, including
  in scan profiles.
- A plugin cannot add a scan mode, change scope handling, or alter an evidence
  export.
- A merge of a database with a different engagement id is refused.
- `export` refuses to write over its own source, and refuses an existing file
  without `--force`.
