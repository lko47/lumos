# ADR-006: One snapshot, many renderings, one evidence export

- **Status:** Accepted.
- **Context:** Every format that reads the database independently drifts: a rule fixed in the Markdown writer stays broken in the SVG writer, and a confidence shown in one place is rounded differently in another.
- **Decision:** All topology renderings (SVG, DOT, Mermaid, the map) read the same rows and the same edge vocabulary, and line weight is the evidence claim in every one of them: solid measured, dashed inferred, bold manual. JSON carries no timestamp, so two exports of an unchanged engagement are byte-identical and diffable. Exactly one export is evidence rather than a rendering - the stored Nmap XML - and it refuses to invent anything: it parses the document before writing and errors when no evidence was kept.
- **Consequences:** A fix to the topology vocabulary lands everywhere at once, and a test can assert that the writers cannot disagree. Users can tell a document from evidence by its command.
