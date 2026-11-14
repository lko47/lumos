# Contributing

## The three gates

Every change must pass all three, and they run in CI:

```sh
PYTHONPATH=src python3 -W error -m unittest discover -s tests
python3 scripts/check_standards.py          # exit 0, no new violations
python3 scripts/check_history_pii.py        # no personal data in any revision
```

If you add a module, regenerate the diagram: `python3 scripts/gen_modules.py`.
If you change the schema, propose it in an ADR first — schema changes are
forward-only and need agreement.

## Standards

The codebase follows the Joint Strike Fighter C++ coding standard (AV rules) as
a style floor, enforced by `scripts/check_standards.py`. Functions stay under
200 lines, parameters under 8, lines under 120 characters. The baseline in
`scripts/av_baseline.json` is **shrink-only**: fix existing violations instead of
adding entries. Reshape a big function (frozen dataclass, tuple, extracted
helper) rather than waiving the rule.

## Never commit personal data

No real subnets, hostnames, MACs, usernames, home paths or email addresses — not
in code, not in fixtures, not in commit messages. Test fixtures use the
documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`),
`.example` hostnames, and `02:00:` MACs. Scaffolding that must contain a real
value gets rewritten before it is committed; the history guard checks every
revision, and a bypass is a bug, not a shortcut.

## Tests must exercise reality

- A unit test with a mock is not proof that a key is reachable or an argv is
  correct. Anything with a UI or a subprocess gets a PTY or real-binary check as
  well.
- Never scan a real network in a test. `127.0.0.1`, `192.0.2.0/24`, fake
  binaries and fixtures only.
- A test that only checks the columns you already thought of will pass while the
  feature leaks. Assert the property, not the implementation.

## Screenshots

`docs/screenshots/*.svg` are generated, never hand-captured:

```sh
python3 -m venv /tmp/shot && /tmp/shot/bin/pip install pyte
PYTHONPATH=src /tmp/shot/bin/python scripts/make_screenshot.py --out docs/screenshots/map.svg
PYTHONPATH=src /tmp/shot/bin/python scripts/make_screenshot.py --out docs/screenshots/scans.svg --keys s
```

Regenerate them when the layout changes. `tests/test_screenshots.py` fails if a
committed image stops coming from demo data or contains a private address.

## Real engines

`tests/test_real_engines.py` runs naabu and rustscan against 127.0.0.1 and skips
when the binary is absent, so CI stays hermetic while a laptop can check the
parsers against real output:

```sh
PATH="$HOME/go/bin:$HOME/.cargo/bin:$PATH" PYTHONPATH=src \
    python3 -m unittest tests.test_real_engines -v
```

masscan needs `CAP_NET_RAW` and cannot be exercised this way; treat its parser as
the least-proven one.

## Commits

One slice per commit, message says what was verified and how. If a claim was not
verified, say so in the message rather than implying it was.

## Reports

User-facing documentation lives in `README.md` (task-oriented),
`docs/PLUGINS.md` (extension surface), `docs/ZENMAP-PARITY.md` (honest gaps) and
`docs/adr/` (decisions). Prefer correcting a document to adding a second one.
