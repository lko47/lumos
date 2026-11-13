# JSF-AV coding standard alignment

This project follows the mechanical parts of *Joint Strike Fighter Air Vehicle
C++ Coding Standards* (Doc. No. 2RDU00001 Rev C, December 2005) where they
translate to Python, and records every deviation the way AV Rule 6 requires.

The standard targets C++ for flight software. Lumos is a standard-library
Python terminal tool, so the mapping is deliberate: rules about headers,
templates, multiple inheritance, signed/unsigned arithmetic and destructors
have no Python analogue and are marked N/A rather than silently ignored.

Run the checker:

```sh
python3 scripts/check_standards.py              # fails on any new violation
python3 scripts/check_standards.py --update-baseline   # after fixing debt
```

`scripts/av_baseline.json` records the violations that existed when the
standard was adopted. The ratchet only turns one way: a violation count may
drop, never rise. Before adopting, 101 deviations existed across the tree,
mostly long lines in `core/scan_store.py`, `core/reports.py` and `cli.py`.

## Conformance summary

| Rule | Requirement | Status | Evidence |
| --- | --- | --- | --- |
| AV 1 | ≤ 200 logical lines per function | enforced | `check_standards.py`; longest function is 168 lines |
| AV 2 | no self-modifying code | enforced | `eval`/`exec`/`compile`/`__import__` calls rejected |
| AV 3 | cyclomatic complexity ≤ 20 | **deviation** | 5 functions exceed it; see register |
| AV 4–7 | deviation approval, documented in the file | adopted | this document is the deviation register |
| AV 15 | defensive checks at boundaries | adopted | schema/`check_database`, XML limits, scope guard, SQL parameter binding |
| AV 30 | `const` instead of `#define` | adapted | module-level named constants (`MAX_LINES`, `_BATCH_SIZE`, `HINTS`) |
| AV 41 | lines ≤ 120 characters | enforced (ratchet) | baseline counts per file |
| AV 43 | no horizontal tabs | enforced | checker |
| AV 44 | consistent indentation | adopted | 4 spaces, enforced by the language |
| AV 45 | `snake_case` identifiers | adopted | all of `src/lumos` |
| AV 47 | identifiers do not begin with `_` | **deviation** | Python has no other way to mark module-private names |
| AV 51 | function and variable names lowercase | adopted | checker-reviewed by eye, exceptions are class names (AV 50) |
| AV 59–61 | braces around blocks, one per line | N/A | Python blocks are structural; the checker bans one-line `if x: y` in new code by review |
| AV 110 | functions take ≤ 7 parameters | **deviation** | drawing helpers take the curses window plus geometry; see register |
| AV 112 | no return of a reference to a local | N/A | the language forbids it |
| AV 126 | one comment style | adapted | docstrings plus `#` comments; no block comments |
| AV 127 | no commented-out code | enforced by review | no dead code found in `src/` |
| AV 133 | every file has an introductory comment | enforced | module docstring check |
| AV 134 | preconditions documented | adapted | docstrings state assumptions (`parse_nmap_xml`, `merge.py`) |
| AV 148 | enums instead of magic integers | adapted | `dataclasses`/literal unions (`status`, `kind`); string literals are the Python enum equivalent |
| AV 151 | no bare numeric literals | **deviation** | geometry and timeouts are named constants, but the ratchet does not yet scan literals |
| AV 162–163 | no signed/unsigned mixing | N/A | Python integers are arbitrary precision |
| AV 192 | final `else` in an `if` chain | adapted | dispatch chains end with an explicit fallback (`_mouse_key`, `decode`, `_component`) |
| AV 204 | side effects in statements only | adopted | no assignment expressions; actions are explicit calls |
| AV 207 | no unencapsulated global data | **deviation** | `mouse._REGISTRY`, `widgets._BACKDROPS`; see register |
| AV 208 | C++ exceptions shall not be used | **deviation** | Python exceptions are the error mechanism; see register |
| AV 210–212 | no assumptions about memory layout or overflow | adopted | no `struct` packing, no pointer arithmetic |
| AV 216 | no premature optimization | adopted | layout caches keyed by inputs, measured in `bench/` |
| AV 217 | prefer compile-time to run-time errors | adapted | `from __future__ import annotations`, module import smoke test, schema validation on open |

## Deviation register (AV Rule 6)

| ID | Rule | Where | Why | Mitigation |
| --- | --- | --- | --- | --- |
| D1 | AV 3 | `map_render.draw_map_panel` (61), `draw_sidebar` (42), `forms.run_form` (27), `flows._watch_scan` (23), `app._run_event_loop` (~24) | Rendering loops and the modal key loops are state machines; splitting them further would spread one screen across several functions with no shared state | Baselines pinned per file; new code must stay under 20; the rendering split is tracked as the next refactor |
| D2 | AV 110 | `widgets.draw_box` (11), `draw_meter`, `label_value`, `key_hint`, `forms._draw` (9), `map_render.draw_map_panel`/`draw_sidebar` (9), `app._draw_frame` (12) | These are pure drawing functions whose parameters are the geometry they draw; a context object would hide the geometry at the call site | Keyword-only arguments after the window; callers always name them |
| D3 | AV 41 | 101 lines at adoption, concentrated in `core/scan_store.py` (19), `core/reports.py` (17), `core/nmap/runner.py` (6), `cli.py` (5) | Pre-existing SQL and report strings | Ratchet: counts may only decrease; new code is written to 120 columns |
| D4 | AV 47 | every module | Python marks non-public names with a leading underscore; there is no `private:` equivalent | Public API is exported through `lumos.cli` and `lumos.services.actions`; tests import only public names plus documented internals |
| D5 | AV 207 | `tui/mouse.py`, `tui/widgets.py` | A curses screen is drawn on one thread, and a dialog opened later must see the same hotspots the frame registered; a per-window side table would duplicate the curses window identity | One instance per module behind functions (`mouse.add`, `mouse.hit`, `set_backdrop`); no other module holds state; documented in each module docstring |
| D6 | AV 208 | whole codebase | Python has no return codes without exceptions; error paths raise typed errors (`DatabaseError`, `MergeError`, `NmapXmlError`, `ScopeConfirmationRequired`) | Exceptions are caught at boundaries (`services.actions._guarded`, `ScanJob._run`), never used for control flow inside a loop |
| D7 | AV 151 | `tui/` geometry | Terminal layout needs many small offsets | Layout constants are named; the literal scan is not yet automated (next step) |

## What the checker does not cover

Static coverage, not proof of correctness. The suite in `tests/` (246 tests)
carries the behavioural evidence; this document and the baseline carry the
style evidence. Anything a machine cannot judge — comment quality, naming
taste, whether an abstraction is honest — is reviewed by hand and, when
deviating, recorded above.
