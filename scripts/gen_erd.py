#!/usr/bin/env python3
"""Generate the Mermaid ER diagrams under docs/architecture from the live schema.

The schema is created in a throwaway directory with ``initialize_database``, so
the diagrams always describe the migrations in ``core/schema.py`` and never an
engagement file. Standard library only; no runtime dependency.

    python3 scripts/gen_erd.py            # rewrite docs/architecture/schema-*.md
    python3 scripts/gen_erd.py --check    # exit 1 if the committed files differ
"""

from __future__ import annotations

import argparse
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from lumos.core.database import initialize_database, open_database  # noqa: E402

DOMAINS: dict[str, tuple[str, list[str], str]] = {
    "scan-data": (
        "Scan data",
        [
            "engagement",
            "networks",
            "vantage_points",
            "vantage_interfaces",
            "vantage_routes",
            "addresses",
            "devices",
            "scans",
            "host_observations",
            "observation_addresses",
            "port_observations",
            "script_observations",
            "trace_paths",
            "trace_hops",
            "raw_scan_evidence",
        ],
        "the engagement root, the scanner's own interfaces and routes, addresses, "
        "devices, scans and the immutable observations a scan writes",
    ),
    "topology": (
        "Topology",
        [
            "engagement",
            "topology_nodes",
            "topology_edges",
            "zones",
            "zone_memberships",
            "manual_nodes",
            "node_positions",
            "edge_decisions",
        ],
        "the graph itself: nodes, typed edges with provenance, derived hubs and "
        "memberships, plus the operator's promoted/rejected link decisions",
    ),
    "review-and-edits": (
        "Review and human edits",
        [
            "engagement",
            "devices",
            "networks",
            "identity_claims",
            "review_items",
            "review_events",
            "duplicate_proposals",
            "duplicate_proposal_events",
            "notes",
            "tags",
            "tag_links",
            "human_edits",
        ],
        "the review queue, duplicate-device proposals, identity claims, notes, tags "
        "and the append-only human-edit log",
    ),
    "merge-and-audit": (
        "Merge and audit",
        [
            "engagement",
            "scans",
            "meta",
            "merge_log",
            "audit_events",
            "scope_rules",
        ],
        "engagement identity, the scan audit trail, engagement-wide scope rules and "
        "one row per merge attempt",
    ),
}


def _schema(path: Path) -> tuple[list[str], dict[str, list[tuple]], dict[str, list[tuple]]]:
    initialize_database(path, "erd generation")
    conn = open_database(path, readonly=True)
    try:
        tables = [
            str(row[0])
            for row in conn.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        columns = {table: list(conn.execute(f"PRAGMA table_info({table})")) for table in tables}
        foreign_keys = {
            table: list(conn.execute(f"PRAGMA foreign_key_list({table})")) for table in tables
        }
        return tables, columns, foreign_keys
    finally:
        conn.close()


def _relation(unique_sets: list[set[str]], fk_columns: set[str]) -> str:
    """Cardinality of a child->parent FK: one-to-one when the FK is unique.

    Only a unique key wholly inside the foreign-key columns makes the link
    one-to-one; a column that merely participates in a wider unique key (for
    example ``ux_topology_edges_natural``) does not.
    """
    for unique in unique_sets:
        if unique and unique <= fk_columns:
            return "||--o|"
    return "||--o{"


def _unique_sets(path: Path, table: str, columns: list[tuple]) -> list[set[str]]:
    conn = open_database(path, readonly=True)
    try:
        sets: list[set[str]] = []
        primary = {str(row[1]) for row in columns if row[5]}
        if primary:
            sets.append(primary)
        for index in conn.execute(f"PRAGMA index_list({table})"):
            if not index[2]:
                continue  # not unique
            names = {str(row[2]) for row in conn.execute(f"PRAGMA index_info({index[1]})")}
            if names:
                sets.append(names)
        return sets
    finally:
        conn.close()


def render_domain(
    path: Path,
    slug: str,
    tables_in_domain: list[str],
    all_tables: list[str],
    columns: dict[str, list[tuple]],
    foreign_keys: dict[str, list[tuple]],
    shows: str,
) -> str:
    present = set(tables_in_domain)
    lines = [
        f"# Schema — {DOMAINS[slug][0]}",
        "",
        f"Shows {shows}.",
        "Leaves out tables from the other schema diagrams and every runtime query, "
        "so a relationship here is a foreign key, not a code path.",
        "Generated by `scripts/gen_erd.py` from the schema `initialize_database` "
        "creates; do not edit by hand.",
        "",
        "```mermaid",
        "erDiagram",
    ]
    for table in tables_in_domain:
        unique_sets = _unique_sets(path, table, columns[table])
        parents: dict[int, str] = {}
        columns_by_fk: dict[int, list[str]] = {}
        for fk in foreign_keys[table]:
            parents[int(fk[0])] = str(fk[2])
            columns_by_fk.setdefault(int(fk[0]), []).append(str(fk[3]))
        for fk_id in sorted(parents):
            parent = parents[fk_id]
            if parent not in present:
                continue
            fk_columns = set(columns_by_fk[fk_id])
            pointer = _relation(unique_sets, fk_columns)
            label = ", ".join(sorted(fk_columns))
            lines.append(f'    {parent} {pointer} {table} : "{label}"')
    for table in tables_in_domain:
        foreign_columns = {
            str(fk[3]) for fk in foreign_keys[table] if str(fk[2]) in present
        }
        lines.append(f"    {table} {{")
        for row in columns[table]:
            name, kind, pk = str(row[1]), str(row[2]), row[5]
            flags = []
            if pk:
                flags.append("PK")
            elif name in foreign_columns:
                flags.append("FK")
            suffix = (" " + " ".join(flags)) if flags else ""
            lines.append(f"        {kind} {name}{suffix}")
        lines.append("    }")
    lines.append("```")
    lines.append("")
    return "\n".join(lines)


def generate(out_dir: Path) -> list[Path]:
    written: list[Path] = []
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "schema.sqlite"
        tables, columns, foreign_keys = _schema(path)
        known = set(DOMAINS)
        mapped = {table for _slug, (_title, names, _shows) in DOMAINS.items() for table in names}
        missing = sorted(set(tables) - mapped)
        if missing:
            raise SystemExit(f"tables without a domain in gen_erd.py: {missing}")
        for slug, (_title, names, shows) in DOMAINS.items():
            unknown = sorted(set(names) - set(tables))
            if unknown:
                raise SystemExit(f"domain {slug} names unknown tables: {unknown}")
            body = render_domain(path, slug, names, tables, columns, foreign_keys, shows)
            target = out_dir / f"schema-{slug}.md"
            written.append(target)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=ROOT / "docs" / "architecture",
        help="directory to write schema-*.md into",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="do not write; exit 1 when a committed file differs from the generated one",
    )
    args = parser.parse_args(argv)
    if not args.check:
        for path in generate(args.out):
            print(path.relative_to(ROOT) if path.is_relative_to(ROOT) else path)
        return 0
    with tempfile.TemporaryDirectory() as tmp:
        fresh = Path(tmp)
        stale = []
        for path in generate(fresh):
            committed = args.out / path.name
            if not committed.exists() or committed.read_text(encoding="utf-8") != path.read_text(
                encoding="utf-8"
            ):
                stale.append(committed.name)
        if stale:
            print("stale generated diagrams: " + ", ".join(sorted(stale)), file=sys.stderr)
            return 1
    print("generated diagrams are current")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
