"""The architecture documents must match the code they describe."""

from __future__ import annotations

import ast
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "lumos"
ARCH = ROOT / "docs" / "architecture"
FORBIDDEN_UPWARD = ("lumos.tui", "lumos.cli", "lumos.services", "lumos.plugins")


def imported_names(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names.add(node.module)
    return names


def relative_targets(path: Path) -> set[str]:
    """Resolve ``from ..x import y`` to absolute module names."""
    parts = path.relative_to(ROOT / "src").with_suffix("").parts
    package = list(parts[:-1])
    tree = ast.parse(path.read_text(encoding="utf-8"))
    targets: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ImportFrom) or not node.level:
            continue
        base = package[: len(package) - (node.level - 1)] if node.level > 1 else package
        module = ".".join(base + ([node.module] if node.module else []))
        targets.add(module)
        for alias in node.names:
            targets.add(f"{module}.{alias.name}" if module else alias.name)
    return targets


class LayeringTests(unittest.TestCase):
    def test_core_does_not_import_ui_or_plugins(self) -> None:
        offenders = []
        for path in sorted((SRC / "core").rglob("*.py")):
            names = imported_names(path) | relative_targets(path)
            for name in sorted(names):
                if any(name == bad or name.startswith(bad + ".") for bad in FORBIDDEN_UPWARD):
                    offenders.append(f"{path.relative_to(ROOT)} -> {name}")
        self.assertEqual(offenders, [])

    def test_services_does_not_import_tui_or_cli(self) -> None:
        offenders = []
        for path in sorted((SRC / "services").rglob("*.py")):
            names = imported_names(path) | relative_targets(path)
            for name in sorted(names):
                if name.startswith(("lumos.tui", "lumos.cli", "lumos.plugins")):
                    offenders.append(f"{path.relative_to(ROOT)} -> {name}")
        self.assertEqual(offenders, [])


class DocumentShapeTests(unittest.TestCase):
    """Every diagram file carries one Mermaid block and the three-line caption."""

    def files(self) -> list[Path]:
        return sorted(path for path in ARCH.glob("*.md") if path.name != "README.md")

    def test_every_file_has_a_caption_and_one_diagram(self) -> None:
        self.assertTrue(self.files())
        for path in self.files():
            with self.subTest(file=path.name):
                text = path.read_text(encoding="utf-8")
                self.assertEqual(text.count("```mermaid"), 1, "expected exactly one diagram")
                lines = [line for line in text.splitlines() if line.strip()]
                self.assertTrue(lines[0].startswith("# "), "missing H1")
                caption = lines[1:5]
                self.assertTrue(caption[0].startswith("Shows "), caption[0][:40])
                self.assertTrue(caption[1].startswith("Leaves out "), caption[1][:40])

    def test_architecture_readme_links_every_diagram(self) -> None:
        index = (ARCH / "README.md").read_text(encoding="utf-8")
        for path in self.files():
            self.assertIn(f"({path.name})", index)


class GeneratedDiagramTests(unittest.TestCase):
    def check(self, script: str) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / script), "--check"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_erd_diagrams_are_current(self) -> None:
        self.check("gen_erd.py")

    def test_module_diagram_is_current(self) -> None:
        self.check("gen_modules.py")


if __name__ == "__main__":
    unittest.main()
