# Inferred links

Shows what `rebuild_inferred` reads, the order the six rules run in, where an observed traceroute suppresses an inferred link, how `edge_decisions` and proxy-ARP change the result, and what the rebuild deletes.
Leaves out the per-address evidence JSON, the UUIDv5 id derivation in `core/ids.py`, and the foreign-hub exemption for `/32`, `/128` and link-local addresses.
Derived from `core/inference.py::_rebuild`, `_plan_vantage`, `_review_mac`, `_prune`, `_prune_hubs` and `core/evidence.py`.

```mermaid
flowchart TD
    I["vantage_interfaces + vantage_routes<br/>(nmap --iflist at scan start)"]
    H["host_observations<br/>reason, reason_ttl, mac"]
    N["networks.cidr<br/>user-declared networks"]
    T["trace_paths<br/>observed hops"]

    I --> P["_plan_vantage per vantage_point"]
    H --> P
    N --> P
    P --> L["local_interface 1.0<br/>root → hub"]
    P --> R{"connected hub, route<br/>or assumed /24,/64?"}
    R --> OBS{"(vantage, host)<br/>observed in trace_paths?"}
    OBS -->|"yes"| SKIP["no host link,<br/>membership kept"]
    OBS -->|"no"| R2{"route for this host?"}
    R2 -->|"no route, connected hub"| ARP["on_link_arp 0.95<br/>ARP/ND + MAC"]
    R2 -->|"no route, connected hub"| ADDR["on_link_address 0.70"]
    R2 -->|"gateway route"| GW["gateway_on_link 0.90<br/>routed_hub 0.50"]
    R2 -->|"no interface and no route"| UNK["unknown_path 0.20 / 0.40<br/>hub relabelled 'path unknown'"]
    MAC["one MAC ≥ 10 hosts<br/>review_items: proxy_arp_suspected"] -.->|"downgrade"| ADDR
    DEC["edge_decisions<br/>rejected / promoted"] --> KEEP{"keep edge?"}
    ARP --> KEEP
    ADDR --> KEEP
    GW --> KEEP
    UNK --> KEEP
    KEEP -->|"rejected"| DROP["edge dropped;<br/>promoted already manual"]
    KEEP -->|"kept"| WRITE["write derived hubs,<br/>edges, memberships"]
    WRITE --> PRUNE["_prune: delete derived=1<br/>edges and zones not regenerated"]
```
