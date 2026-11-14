# Security policy

Lumos runs a network scanner and stores what it finds. Two classes of problem
matter here, and they are handled the same way.

## Reporting

Open a **private security advisory** on this repository (Security → Advisories →
Report a vulnerability). Please do not open a public issue for a vulnerability,
and do not attach an engagement database, a real scan export or a screenshot of a
live network — those contain somebody's addressing. A sanitised database
(`lumos export ORIGINAL COPY`) is safe to attach.

Expect an acknowledgement within a few days. There is no bounty.

## What counts

- **Anything that escapes the scope guard.** A scan of a target outside the
  engagement's scope, or a way to make a target string behave as a command flag.
- **Anything that executes a command with a shell**, or that lets scan input
  reach a shell.
- **Parser escapes**: an Nmap XML document that crashes the importer, exhausts
  memory, reads a local file, or injects markup into a report.
- **Proof that the pseudonymised export leaks**: any original address, hostname,
  MAC, path or note body surviving `lumos export`.
- **A plugin that runs without being placed in a plugin directory**, or one that
  can alter scope, scanning or an evidence export.
- **Personal data in the repository or its history**, including in tests,
  fixtures and commit messages.

## Supported versions

The project ships from `main`; there are no maintained release branches. Fixes
land on `main` and are noted in the commit that makes them.

## Threat model, briefly

Scan output, imported XML and imported databases are treated as hostile.
Engagement databases are treated as sensitive: they are written owner-only, and
sharing is a rewrite, not a copy. An operator's terminal and local filesystem are
trusted; a plugin is arbitrary code running with the operator's privileges, which
is why it must be installed deliberately.
