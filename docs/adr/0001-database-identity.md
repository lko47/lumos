# ADR-001: Stable identity and merge-ready schema v1

- **Status:** Accepted for Phase 1; schema changes remain forward-only.
- **Context:** Engagement databases are built independently and later merged. Local integer row IDs cannot identify records across files, and scan observations must remain immutable.
- **Decision:** Cross-file entities use random UUID text primary keys. Device identity is separate from scoped address identity. Scan observations, provenance, topology claims, human edits, and review events are separate records. Schema version is stored in `PRAGMA user_version`; database identity is fixed in `PRAGMA application_id` (`0x4C554D53`, ASCII `LUMS`). Version 1 includes the relations and indexes required for later bounded-memory merge work. UTC timestamps use ISO-8601 text ending in `Z`.
- **Consequences:** Merge logic can union immutable UUID records and preserve conflicting edits. Schema evolution must add forward-only migrations; old schemas are never silently rewritten backward. The application ID is a format identifier, not a security boundary.
- **Deferred:** Deterministic conflict ordering, read-only untrusted-file merge, and migration compatibility tests are implemented in later phases.
