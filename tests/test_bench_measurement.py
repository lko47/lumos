"""The scale benchmark must report the post-scan inference cost (F5)."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_benchmark():
    spec = importlib.util.spec_from_file_location(
        "lumos_map_benchmark", ROOT / "bench" / "map_benchmark.py"
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load bench/map_benchmark.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class BenchmarkMeasurementTests(unittest.TestCase):
    def test_measure_reports_the_inference_rebuild_cost(self) -> None:
        benchmark = load_benchmark()
        result = benchmark.measure(300)
        self.assertIn("rebuild_ms", result)
        self.assertGreater(float(result["rebuild_ms"]), 0.0)
        self.assertGreater(int(result["rebuild_edges"]), 0)
        self.assertIn("rebuild_inferred", benchmark.__doc__ or "")


if __name__ == "__main__":
    unittest.main()
