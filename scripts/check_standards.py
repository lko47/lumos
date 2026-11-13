#!/usr/bin/env python3
"""Check the mechanical subset of the JSF-AV coding rules on ``src/lumos``.

Rules enforced (numbering from Doc. No. 2RDU00001 Rev C):

=========================  =========================================
AV Rule 1                  no function longer than 200 logical lines
AV Rule 3                  cyclomatic complexity 20 or less
AV Rule 41                 lines of 120 characters or fewer
AV Rule 43                 no horizontal tabs
AV Rule 110                no function with more than 7 parameters
AV Rule 133                every source file starts with a docstring
=========================  =========================================

Rules that cannot be expressed mechanically (or that Python contradicts)
are recorded with their rationale in docs/standards/JSF-AV-ALIGNMENT.md.
Standard library only; runs offline.

    python3 scripts/check_standards.py            # report violations
    python3 scripts/check_standards.py --quiet    # exit status only
"""

from __future__ import annotations

import argparse
import ast
import json
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "lumos"
BASELINE = ROOT / "scripts" / "av_baseline.json"
MAX_LINES = 120
MAX_FUNCTION_LINES = 200
MAX_COMPLEXITY = 20
MAX_PARAMETERS = 7


@dataclass(frozen=True)
class Violation:
    rule: str
    path: Path
    line: int
    detail: str

    def render(self) -> str:
        return f"{self.path.relative_to(ROOT)}:{self.line}: AV Rule {self.rule}: {self.detail}"


def _functions(tree: ast.AST) -> list[ast.FunctionDef | ast.AsyncFunctionDef]:
    return [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    ]


def _complexity(node: ast.AST) -> int:
    """McCabe complexity: 1 plus each decision point inside the function."""
    score = 1
    for child in ast.walk(node):
        if isinstance(child, (ast.If, ast.For, ast.While, ast.ExceptHandler, ast.With, ast.AsyncFor)):
            score += 1
        elif isinstance(child, ast.BoolOp):
            score += len(child.values) - 1
        elif isinstance(child, ast.IfExp):
            score += 1
        elif isinstance(child, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            score += 1
    return score


def _line_checks(path: Path) -> list[Violation]:
    problems: list[Violation] = []
    text = path.read_text(encoding="utf-8")
    for number, line in enumerate(text.splitlines(), start=1):
        if len(line) > MAX_LINES:
            problems.append(Violation("41", path, number, f"{len(line)} characters"))
        if "\t" in line:
            problems.append(Violation("43", path, number, "horizontal tab"))
    return problems


def _tree_checks(path: Path, tree: ast.AST) -> list[Violation]:
    problems: list[Violation] = []
    if ast.get_docstring(tree) is None:
        problems.append(Violation("133", path, 1, "module docstring missing"))
    for node in _functions(tree):
        body_lines = (node.end_lineno or node.lineno) - node.lineno + 1
        if body_lines > MAX_FUNCTION_LINES:
            problems.append(
                Violation("1", path, node.lineno, f"{node.name} is {body_lines} lines")
            )
        score = _complexity(node)
        if score > MAX_COMPLEXITY:
            problems.append(
                Violation("3", path, node.lineno, f"{node.name} complexity {score}")
            )
        parameters = (
            list(node.args.posonlyargs)
            + list(node.args.args)
            + list(node.args.kwonlyargs)
        )
        if len(parameters) > MAX_PARAMETERS:
            problems.append(
                Violation("110", path, node.lineno, f"{node.name} takes {len(parameters)} parameters")
            )
    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and node.type is None:
            problems.append(Violation("208", path, node.lineno, "bare except clause"))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in {"eval", "exec", "compile", "__import__"}:
                problems.append(
                    Violation("2", path, node.lineno, f"{node.func.id}() runs code from data")
                )
    return problems


def check_file(path: Path) -> list[Violation]:
    source = path.read_text(encoding="utf-8")
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:  # a file that will not parse cannot conform
        return [Violation("8", path, exc.lineno or 1, f"syntax error: {exc.msg}")]
    return _line_checks(path) + _tree_checks(path, tree)


def check_tree(root: Path = SRC) -> list[Violation]:
    problems: list[Violation] = []
    for path in sorted(root.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        problems.extend(check_file(path))
    problems.sort(key=lambda item: (str(item.path), item.line))
    return problems


def load_baseline() -> dict[str, int]:
    """Read the accepted-debt counts; a missing file means zero tolerance."""
    if not BASELINE.exists():
        return {}
    try:
        data = json.loads(BASELINE.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"invalid baseline: {exc}", file=sys.stderr)
        return {}
    return {str(key): int(value) for key, value in data.items()}


def _key(problem: Violation) -> str:
    """Stable baseline key, also usable for files outside the repository."""
    try:
        path = problem.path.relative_to(ROOT).as_posix()
    except ValueError:
        path = problem.path.as_posix()
    return f"{problem.rule}:{path}"


def count_by_rule_and_file(problems: list[Violation]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for problem in problems:
        key = _key(problem)
        counts[key] = counts.get(key, 0) + 1
    return counts


def write_baseline(problems: list[Violation]) -> None:
    counts = count_by_rule_and_file(problems)
    BASELINE.write_text(json.dumps(counts, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def excess(problems: list[Violation], baseline: dict[str, int]) -> list[Violation]:
    """Return only the violations beyond the recorded debt (the ratchet)."""
    seen: dict[str, int] = {}
    failures: list[Violation] = []
    for problem in problems:
        key = _key(problem)
        seen[key] = seen.get(key, 0) + 1
        if seen[key] > baseline.get(key, 0):
            failures.append(problem)
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quiet", action="store_true", help="print nothing, only set the exit code")
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="record the current violations as accepted debt",
    )
    args = parser.parse_args(argv)
    problems = check_tree()
    if args.update_baseline:
        write_baseline(problems)
        print(f"recorded {len(problems)} accepted deviation(s) in {BASELINE.relative_to(ROOT)}")
        return 0
    failures = excess(problems, load_baseline())
    if failures and not args.quiet:
        for problem in failures:
            print(problem.render())
        print(f"\n{len(failures)} new violation(s); {len(problems)} total incl. accepted debt",
              file=sys.stderr)
    elif not args.quiet:
        print(
            f"no new violations ({len(problems)} accepted deviation(s) in the baseline)"
        )
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
