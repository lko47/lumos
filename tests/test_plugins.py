"""The plugin surface: versioned, per-file, and unable to take Lumos down."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lumos.core import plugins
from lumos.tui import theme

GOOD_EXPORTER = '''
PLUGIN_API = 1
PLUGIN_KIND = "exporter"
PLUGIN_NAME = "textlist"


def export(database, output):
    with open(output, "w", encoding="utf-8") as stream:
        stream.write(database + "\\n")
    return "wrote a list"
'''

GOOD_THEME = '''
PLUGIN_API = 1
PLUGIN_KIND = "theme"
PLUGIN_NAME = "sunset"
THEME = {"title": {"fg": 208, "fg16": 3}, "device": {"fg": 250}}
'''


class PluginLoadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.directory = Path(self.tmp.name)

    def _write(self, name: str, body: str) -> Path:
        path = self.directory / name
        path.write_text(body, encoding="utf-8")
        return path

    def test_a_valid_exporter_loads_and_runs(self) -> None:
        self._write("good.py", GOOD_EXPORTER)
        registry = plugins.load_plugins(directories=(self.directory,))
        self.assertEqual(sorted(registry.exporters), ["textlist"])
        self.assertEqual(registry.errors, ())
        output = self.directory / "out.txt"
        self.assertEqual(registry.exporters["textlist"].export("db", str(output)), "wrote a list")
        self.assertTrue(output.exists())

    def test_a_wrong_api_version_is_refused_by_name(self) -> None:
        self._write("old.py", GOOD_EXPORTER.replace("PLUGIN_API = 1", "PLUGIN_API = 99"))
        registry = plugins.load_plugins(directories=(self.directory,))
        self.assertEqual(registry.exporters, {})
        self.assertIn("plugin API 99 is not 1", registry.errors[0])

    def test_a_broken_plugin_does_not_stop_the_others(self) -> None:
        self._write("explodes.py", "raise RuntimeError('on purpose')\n")
        self._write("good.py", GOOD_EXPORTER)
        registry = plugins.load_plugins(directories=(self.directory,))
        self.assertIn("textlist", registry.exporters)
        self.assertTrue(any("on purpose" in error for error in registry.errors))

    def test_kind_and_name_are_validated(self) -> None:
        self._write("kind.py", GOOD_EXPORTER.replace('"exporter"', '"daemon"'))
        self._write("name.py", GOOD_EXPORTER.replace('PLUGIN_NAME = "textlist"',
                                                     'PLUGIN_NAME = "../escape"'))
        registry = plugins.load_plugins(directories=(self.directory,))
        self.assertEqual(registry.exporters, {})
        self.assertEqual(len(registry.errors), 2)

    def test_an_exporter_without_the_function_is_refused(self) -> None:
        self._write("nofunc.py", GOOD_EXPORTER.replace("def export", "def emits"))
        registry = plugins.load_plugins(directories=(self.directory,))
        self.assertIn("must define export", registry.errors[0])

    def test_duplicate_names_keep_the_first_and_report_the_second(self) -> None:
        self._write("a.py", GOOD_EXPORTER)
        self._write("b.py", GOOD_EXPORTER)
        registry = plugins.load_plugins(directories=(self.directory,))
        self.assertEqual(len(registry.exporters), 1)
        self.assertIn("already taken", registry.errors[0])

    def test_a_symlink_out_of_the_plugin_directory_is_not_followed(self) -> None:
        outside = self.directory.parent / f"{self.directory.name}-outside.py"
        outside.write_text(GOOD_EXPORTER, encoding="utf-8")
        self.addCleanup(outside.unlink)
        (self.directory / "link.py").symlink_to(outside)
        registry = plugins.load_plugins(directories=(self.directory,))
        self.assertEqual(registry.exporters, {})
        self.assertIn("symlink points outside", registry.errors[0])

    def test_disabling_removes_the_whole_surface(self) -> None:
        self._write("good.py", GOOD_EXPORTER)
        self.assertEqual(
            plugins.load_plugins(enabled=False, directories=(self.directory,)).exporters, {}
        )
        with mock.patch.dict(os.environ, {"LUMOS_NO_PLUGINS": "1"}):
            self.assertEqual(
                plugins.load_plugins(directories=(self.directory,)).exporters, {}
            )

    def test_the_environment_names_directories_to_search(self) -> None:
        self._write("good.py", GOOD_EXPORTER)
        with mock.patch.dict(os.environ, {"LUMOS_PLUGIN_PATH": str(self.directory)}):
            registry = plugins.load_plugins()
        self.assertIn("textlist", registry.exporters)


class PluginThemeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.addCleanup(theme.THEMES.pop, "sunset", None)

    def test_a_theme_plugin_becomes_a_palette(self) -> None:
        directory = Path(self.tmp.name)
        (directory / "sunset.py").write_text(GOOD_THEME, encoding="utf-8")
        registry = plugins.load_plugins(directories=(directory,))
        registered = theme.register_plugin_themes(
            {name: item.theme for name, item in registry.themes.items()}
        )
        self.assertEqual(registered, ("sunset",))
        self.assertEqual(theme.THEMES["sunset"]["title"].fg, 208)
        self.assertEqual(theme.THEMES["sunset"]["title"].fg16, 3)
        self.assertEqual(theme.THEMES["sunset"]["device"].fg, 250)
        self.assertIn("sunset", theme.cycle_order(), "a plugin theme must be reachable")
        self.assertEqual(theme.next_theme("matrix"), "sunset")
        self.assertEqual(theme.next_theme("sunset"), "aurora")

    def test_a_plugin_cannot_replace_a_built_in_theme(self) -> None:
        original = theme.THEMES["aurora"]
        registered = theme.register_plugin_themes({"aurora": {"title": {"fg": 1}}})
        self.assertEqual(registered, ())
        self.assertIs(theme.THEMES["aurora"], original)


if __name__ == "__main__":
    unittest.main()
