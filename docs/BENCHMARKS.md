# Benchmarks

Measured with `scripts/benchmark.py` on a generated demo engagement (11 hosts, 5 scans, 3 zones, 15 nodes, 14 links, 616 KiB database). No real network is involved. Each row is the median of five runs; the demo build and the merge use three.

Intel(R) Core(TM) i7-8665U CPU @ 1.90GHz · 8 cores · Python 3.14.9 · SQLite 3.53.1 · Linux 7.2.14-arch1-1

| Operation | Median |
| --- | --- |
| generate demo engagement (11 hosts, 5 scans) | 100.7 ms |
| open the map snapshot | 2.8 ms |
| render the map as plain text | 2.9 ms |
| build the JSON report | 6.7 ms |
| build the DOT export | 1.8 ms |
| build the SVG report | 1.1 ms |
| build the Markdown report | 4.8 ms |
| merge two engagements | 13.0 ms |

Peak Python memory while opening the map: 43 KiB.

## How each row is measured

- **generate demo engagement** — `demo.build_demo` end to end: three scans written through `ScanWriter`, the inference pass, a note, tags and a review decision.
- **open the map snapshot** — `load_map_snapshot`, which is what the interface calls on every reload (the file watcher calls it when the database changes).
- **render the map as plain text** — snapshot plus `render_plain_snapshot`, the same renderer used when stdout is redirected.
- **reports** — the pure build functions (`build_json_report`, `build_dot_report`, `iter_svg_report`, `iter_markdown_report`), excluding disk writes.
- **merge two engagements** — `merge_engagement` on two copies of the same demo file, which measures the write path including its idempotent conflict handling.

## What these numbers do not say

- **No interactive frame rate.** Drawing a frame is measured here only as a pure function of the snapshot; terminal I/O, the animation tick and the real terminal's own cost are outside this measurement. Do not read "3.3 ms" as input latency.
- **One small engagement.** 11 hosts is a demo, not a scale test. Nothing here says how a 10,000-host engagement behaves; that has not been measured, and no number is invented for it.
- **One machine.** Numbers move with CPU, filesystem and Python build; the row above names exactly what was used, so a reader can tell whether a comparison is meaningful.

## Scale, measured

`bench/map_benchmark.py` builds a throwaway engagement with N synthetic hosts
using the same deterministic ids as the application, then measures the read and
render path at the interface's default bound and unbounded. Same machine as
above, Python 3.14.9.

| Hosts | Database | Load (default bound) | Load (all nodes) | Frame at 110x32 | `rebuild_inferred` |
| --- | --- | --- | --- | --- | --- |
| 10,000 | 31.8 MB | 29.3 ms | 24 ms | 3.4 ms | 1.20 s |
| 100,000 | 315 MB | 460 ms | 436 ms | 16.9 ms | 18.0 s |

Read this with the shape of the tool in mind:

- **Drawing stays inside the frame budget.** A full frame at 100,000 hosts is
  16.9 ms against the 50 ms budget; the default 2,000-node viewport is what an
  operator actually sees, and it loads in under half a second.
- **`rebuild_inferred` is the expensive path**, and it runs synchronously on the
  calling thread after a scan or an import: 18 s at 100,000 hosts. That is a real
  limitation, now measured rather than assumed. It is not done on every frame,
  but it does block the caller, and nothing in this repository claims otherwise.
- The benchmark builds its fixture with bulk SQL, so the numbers describe
  reading and inference, not the Nmap writer's per-host path.
