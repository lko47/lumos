# Zenmap parity

Zenmap is the reference GUI for Nmap. Lumos is a terminal mapper with a different centre of gravity — a topology you can navigate, and evidence you can trust. This table says what carries over and what does not, without softening either.

| Capability | Zenmap | Lumos | Notes |
| --- | --- | --- | --- |
| Run Nmap with a command line | yes (wizard) | yes | Lumos shows the exact argv before running and refuses anything the runner does not allow |
| Scan profiles | yes, editable | partial | five presets (discovery, connect, service, udp, custom); not user-editable files yet |
| Host list with services | yes, sortable columns | yes | hosts view, per-host detail with ports, products and versions |
| Topology view | yes, static radial | yes | interactive: pan, zoom, collapse hubs, path highlighting, pinning, animation |
| Nmap XML import | yes | yes | streamed, bounded, and treated as hostile input |
| Save and reopen a scan | yes | yes | engagement database, not a loose XML file |
| Compare two scans | via Ndiff | yes | address-keyed diff built in; `lumos compare` |
| Search/filter | yes | partial | `/` searches hosts and labels; no port-expression language |
| NSE script output | yes, per host | partial | stored and shown as script observations; no script browser UI |
| Trace route display | yes | yes | hop view with unknown/assumed hops labelled as such |
| Export reports | XML, HTML from Ndiff | yes, eight formats | markdown, SVG, JSON, CSV, HTML, DOT, Mermaid, stored Nmap XML |
| Plugin surface | no | yes | exporters and themes only, versioned and validated |
| Editing a scan result by hand | limited | yes | notes, tags, manual pins, review decisions — append-only |
| Privileged scan modes | via GUI elevation | partial | `-sS` works when Lumos itself has the privilege; no elevation prompt |
| Windows GUI | yes | no | terminal only, Linux/macOS |
| Guest/remote mode | no | no | not planned |

## Deliberate differences

- **No `-oA` / `-oX` to a second file.** Lumos parses Nmap's XML stream itself; a second copy on disk is a leak waiting to happen (`-oN`/`-oG` are supported).
- **No traffic generation beyond Nmap and the other enumerators.** No exploitation, no credential access.
- **Inferred links are never drawn as measured.** Zenmap draws a radial topology from stored XML; Lumos distinguishes measured, inferred, imported and manual links in both the map and every export.
