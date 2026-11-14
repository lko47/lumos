"""Measure the operations a user waits on, and say how each was measured.

Run from the repository root::

    PYTHONPATH=src python3 scripts/benchmark.py

Every row is the median of ``REPEATS`` runs on a generated demo engagement, so
no real network is involved. TUI frame cost is measured by driving the renderer
directly (no terminal), which is the part Lumos controls; terminal I/O is the
terminal's business and is not measured here.
"""

from __future__ import annotations

import json
import os
import platform
import shutil
import sqlite3
import statistics
import sys
import tempfile
import time
import tracemalloc
from pathlib import Path

REPEATS = 5
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lumos.core import reports  # noqa: E402
from lumos.core.merge import merge_engagement  # noqa: E402
from lumos.services import demo  # noqa: E402
from lumos.services.map_view import load_map_snapshot, render_plain_snapshot  # noqa: E402


def _time(action, repeats: int = REPEATS) -> float:
    samples = []
    for _ in range(repeats):
        start = time.perf_counter()
        action()
        samples.append(time.perf_counter() - start)
    return statistics.median(samples)


def _machine() -> dict[str, str]:
    cpu = "unknown"
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                cpu = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    return {
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "platform": f"{platform.system()} {platform.release()}",
        "cpu": cpu,
        "cores": str(os.cpu_count() or 0),
    }


def run() -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        first = Path(tmp) / "one.sqlite"
        second = Path(tmp) / "two.sqlite"
        sample = Path(tmp) / "sample.sqlite"
        built = _time(lambda: demo.build_demo(sample, overwrite=True), repeats=3)
        demo.build_demo(first)
        # Merging needs one engagement identity in both files: copy rather than
        # generate, otherwise the merge guard refuses (as it should).
        shutil.copy2(first, second)

        timings = {
            "generate demo engagement (11 hosts, 5 scans)": built,
            "open the map snapshot": _time(lambda: load_map_snapshot(first)),
            "render the map as plain text": _time(lambda: render_plain_snapshot(load_map_snapshot(first))),
            "build the JSON report": _time(lambda: reports.build_json_report(first)),
            "build the DOT export": _time(lambda: reports.build_dot_report(first)),
            "build the SVG report": _time(
                lambda: "".join(reports.iter_svg_report(first))
            ),
            "build the Markdown report": _time(
                lambda: list(reports.iter_markdown_report(first))
            ),
            "merge two engagements": _time(
                lambda: merge_engagement(first, second), 3
            ),
        }

        database_bytes = sample.stat().st_size
        tracemalloc.start()
        load_map_snapshot(first)
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()

    return {
        "machine": _machine(),
        "timings": {name: value for name, value in timings.items()},
        "peak_bytes": peak,
        "database_bytes": database_bytes,
    }


def main() -> int:
    result = run()
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
        return 0
    machine = result["machine"]
    print(f"# Benchmarks\n")
    print(f"Python {machine['python']} · SQLite {machine['sqlite']} · "
          f"{machine['platform']} · {machine['cores']} cores · {machine['cpu']}")
    print("\n| Operation | Median |")
    print("| --- | --- |")
    for name, seconds in result["timings"].items():
        print(f"| {name} | {seconds * 1000:.1f} ms |")
    print(f"\nPeak Python memory while opening the map: {result['peak_bytes'] / 1024:.0f} KiB")
    print(f"Database size: {result['database_bytes'] / 1024:.0f} KiB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
