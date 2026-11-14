# ADR-004: Inference is labelled, and identity is never auto-merged

- **Status:** Accepted.
- **Context:** A map that guesses looks identical to a map that measured. Worse, a guessed link can be copied into a report and outlive the scan that produced it. The same applies to identity: two observations that share an address are probably one device, but a wrong merge rewrites history with no way to tell what was observed.
- **Decision:** Every topology edge carries `edge_type` (`traceroute`, `alternate`, `inferred`, `manual`, `imported`), a `source_kind`, and a confidence. Inference writes only `inferred` edges, from rules with names, and every rendering (map line style, DOT, Mermaid, Markdown, SVG) distinguishes inferred from measured. Device identity is keyed per observation; when two observations look like one device, Lumos records a `duplicate_proposal` and merges nothing until a human decides, and the decision is an append-only event.
- **Consequences:** A reader of any export can tell what was measured from what was reasoned. Guesses can be rejected once and stay rejected. The map may show more nodes than a human would draw until duplicates are decided, which is the honest state.
- **Deferred:** Zone membership is derived; only manual nodes and zone edits are human claims.
