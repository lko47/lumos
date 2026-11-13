"""The JSF-AV subset stays enforced: no new violations, and real ones are caught."""

from __future__ import annotations

import importlib.util
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_standards.py"


def _load_checker():
    spec = importlib.util.spec_from_file_location("check_standards", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError("could not load scripts/check_standards.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["check_standards"] = module
    spec.loader.exec_module(module)
    return module


CHECKER = _load_checker()


class SourceConformanceTests(unittest.TestCase):
    def test_no_new_violations_against_the_baseline(self) -> None:
        problems = CHECKER.check_tree()
        failures = CHECKER.excess(problems, CHECKER.load_baseline())
        self.assertEqual([item.render() for item in failures], [])

    def test_baseline_only_shrinks(self) -> None:
        counts = CHECKER.count_by_rule_and_file(CHECKER.check_tree())
        baseline = CHECKER.load_baseline()
        grown = {
            key: (value, baseline.get(key, 0))
            for key, value in counts.items()
            if value > baseline.get(key, 0)
        }
        self.assertEqual(grown, {})


class CheckerDetectionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def _write(self, name: str, body: str) -> Path:
        path = self.root / name
        path.write_text(body, encoding="utf-8")
        return path

    def test_long_line_is_reported(self) -> None:
        path = self._write("long.py", '"""Doc."""\nVALUE = "' + "x" * 130 + '"\n')
        rules = [item.rule for item in CHECKER.check_file(path)]
        self.assertIn("41", rules)

    def test_tabs_are_reported(self) -> None:
        path = self._write("tabbed.py", '"""Doc."""\nVALUE = 1  # tab\there\n')
        rules = [item.rule for item in CHECKER.check_file(path)]
        self.assertIn("43", rules)

    def test_complex_function_is_reported(self) -> None:
        branches = "".join(f"    if x == {index}:\n        return {index}\n" for index in range(21))
        path = self._write("complex.py", '"""Doc."""\n\n\ndef f(x: int) -> int:\n' + branches + "    return -1\n")
        rules = [item.rule for item in CHECKER.check_file(path)]
        self.assertIn("3", rules)

    def test_eval_is_reported(self) -> None:
        path = self._write("dynamic.py", '"""Doc."""\n\n\ndef f(text: str):\n    return eval(text)\n')
        rules = [item.rule for item in CHECKER.check_file(path)]
        self.assertIn("2", rules)

    def test_missing_docstring_is_reported(self) -> None:
        path = self._write("bare.py", "VALUE = 1\n")
        rules = [item.rule for item in CHECKER.check_file(path)]
        self.assertIn("133", rules)

    def test_excess_only_returns_growth(self) -> None:
        path = self._write("long2.py", '"""Doc."""\nVALUE = "' + "y" * 130 + '"\n')
        problems = CHECKER.check_file(path)
        key = next(iter(CHECKER.count_by_rule_and_file(problems)))
        self.assertEqual(CHECKER.excess(problems, {key: 1}), [])
        self.assertEqual(len(CHECKER.excess(problems, {})), len(problems))


if __name__ == "__main__":
    unittest.main()
