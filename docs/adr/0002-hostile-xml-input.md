# ADR-002: Nmap XML is parsed as hostile input

- **Status:** Accepted.
- **Context:** Scan output is the one place an untrusted party can push structured data into Lumos: a host that answers with a crafted `<hostname>`, a doctype with entity definitions, a file truncated mid-document, or a document that never ends. The importer runs on an operator's machine and writes to a database that is later shared.
- **Decision:** XML is consumed as a byte stream with `XMLPullParser`, never loaded whole. Entity declarations and any doctype other than `<!DOCTYPE nmaprun>` are rejected. Depth, host count and total bytes are bounded. Every text field passes through `sanitize_text` with an explicit character limit before it reaches SQL. A truncated document yields the hosts it completed, then raises `TruncatedNmapXmlError`, so a partial import is reported as partial rather than as complete.
- **Consequences:** Worst-case memory is a fixed budget, not the file size. A malformed document fails loudly at a known point. Field limits mean a hostile 10 MB hostname is stored as a truncated string, not a denial of service.
- **Deferred:** Script output is stored as text and rendered as text; no script interpreter or HTML rendering is ever applied to it.
