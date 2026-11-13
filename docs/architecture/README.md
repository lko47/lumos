# Architecture diagrams

Mermaid-only diagrams of Lumos as it is implemented at this commit. Nothing
here is generated into an image or a PDF; GitHub, the VS Code preview and
`mmdc` all read the fenced blocks directly.

Conventions:

- Every box, arrow and label names a real module, function, table or thread
  from `src/lumos`; nothing is invented.
- Anything designed but not built is drawn with a dashed edge and the word
  **planned**, and appears only where the plan needs it.
- Each file opens with a three-line caption: what it shows, what it leaves
  out, and the code it was derived from.
- Diagrams are kept small and split rather than shrunk; if one grows past
  about fifteen nodes it belongs in two files.

| File | Shows |
| --- | --- |
| [context.md](context.md) | operator, scanner host, installed Nmap, engagement file, merge source, reports |
| [layers.md](layers.md) | `core` / `services` / `cli` / `tui` and the allowed import direction (plugins planned) |
| [scan-sequence.md](scan-sequence.md) | one scan from the form or CLI to the stored rows and the refreshed map |
| [threads.md](threads.md) | the six threads, their queues and which of them own a SQLite connection |
| [schema-scan-data.md](schema-scan-data.md) | engagement, vantage, scans, observations, evidence |
| [schema-topology.md](schema-topology.md) | nodes, edges, hubs, memberships, link decisions |
| [schema-review-and-edits.md](schema-review-and-edits.md) | review queue, duplicate proposals, notes, tags, human edits |
| [schema-merge-and-audit.md](schema-merge-and-audit.md) | engagement identity, scope rules, audit trail, merge log |
| [inferred-links.md](inferred-links.md) | `rebuild_inferred` inputs, rule order, overrides, cleanup |
| [merge-sequence.md](merge-sequence.md) | source validation, uid check, copy, log, rebuild |
| [modules.md](modules.md) | package import graph generated from `ast` |

## Regenerating

The ER diagrams and the module graph are generated from the code, not written
by hand:

```sh
python3 scripts/gen_erd.py          # docs/architecture/schema-*.md
python3 scripts/gen_modules.py      # docs/architecture/modules.md
python3 scripts/gen_erd.py --check  # exit 1 when a committed copy is stale
python3 scripts/gen_modules.py --check
```

`tests/test_architecture.py` runs both `--check` modes, so a schema or import
change that is not reflected here fails the suite. Both scripts use only the
standard library: `gen_erd.py` creates a throwaway database with
`initialize_database` and reads `sqlite_master`/`PRAGMA` from it, and
`gen_modules.py` parses files with `ast` without importing them.

## Validating the Mermaid

`@mermaid-js/mermaid-cli` (`mmdc`) was installed into a scratch npm prefix for
this work, but it cannot launch without a Chromium build, and the Puppeteer
browser download did not complete in this environment. **The diagrams are
therefore not render-validated.** They are checked structurally instead: the
test suite requires exactly one `mermaid` block and the three-line caption per
file, and both generators only ever emit node/relationship syntax verified by
inspection. To validate locally:

```sh
npx --yes @mermaid-js/mermaid-cli -i docs/architecture/scan-sequence.md -o /tmp/out.svg
```

or open the files in a Mermaid-capable Markdown preview.
