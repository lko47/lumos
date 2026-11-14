"""A deliberately small plugin surface: exporters and colour themes.

A plugin is one Python file in one of two directories, declaring an API version
and a kind. Anything else is refused with a sentence, per file, so one broken
plugin cannot take the others - or Lumos - down with it.

Importing a plugin runs its code, which no amount of validation makes safe.
The defence is consent: plugins are only loaded from directories the operator
names explicitly (``LUMOS_PLUGIN_PATH``, or ``$XDG_CONFIG_HOME/lumos/plugins``),
``--no-plugins`` (or ``LUMOS_NO_PLUGINS=1``) disables the whole surface, and a
plugin file that is a symlink out of its directory is ignored rather than
followed.
"""

from __future__ import annotations

import importlib.util
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

PLUGIN_API_VERSION = 1
KINDS = ("exporter", "theme")
ENV_PATH = "LUMOS_PLUGIN_PATH"
ENV_DISABLE = "LUMOS_NO_PLUGINS"
NAME_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


class PluginError(ValueError):
    """A plugin that will not be loaded, with the reason in the sentence."""


@dataclass(frozen=True)
class Plugin:
    name: str
    kind: str
    api: int
    path: Path
    export: object = None
    theme: dict = field(default_factory=dict)


@dataclass(frozen=True)
class PluginRegistry:
    exporters: dict[str, Plugin] = field(default_factory=dict)
    themes: dict[str, Plugin] = field(default_factory=dict)
    errors: tuple[str, ...] = ()

    def exporter(self, name: str) -> Plugin | None:
        return self.exporters.get(name)


def plugin_directories(extra: tuple[str | Path, ...] = ()) -> tuple[Path, ...]:
    """Where plugins are looked for: explicitly named places only."""
    directories: list[Path] = [Path(item).expanduser() for item in extra]
    for item in os.environ.get(ENV_PATH, "").split(os.pathsep):
        if item.strip():
            directories.append(Path(item).expanduser())
    config = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    directories.append(Path(config) / "lumos" / "plugins")
    seen: list[Path] = []
    for directory in directories:
        resolved = directory.absolute()
        if resolved not in seen:
            seen.append(resolved)
    return tuple(seen)


def disabled() -> bool:
    return os.environ.get(ENV_DISABLE, "").strip().lower() in {"1", "yes", "true"}


def _inside(path: Path, directory: Path) -> bool:
    try:
        path.resolve().relative_to(directory.resolve())
    except ValueError:
        return False
    return True


def _module_name(path: Path, index: int) -> str:
    return f"lumos_plugin_{index}_{re.sub(r'[^a-z0-9]', '_', path.stem.lower())}"


def _import(path: Path, index: int) -> object:
    spec = importlib.util.spec_from_file_location(_module_name(path, index), path)
    if spec is None or spec.loader is None:
        raise PluginError(f"{path.name}: not importable as a module")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # a plugin's own failure must not be fatal to Lumos
        sys.modules.pop(spec.name, None)
        raise PluginError(f"{path.name}: failed while loading: {exc}") from exc
    return module


def _validate(path: Path, module: object) -> Plugin:
    api = getattr(module, "PLUGIN_API", None)
    if api is None:
        raise PluginError(f"{path.name}: no PLUGIN_API version")
    if not isinstance(api, int) or api != PLUGIN_API_VERSION:
        raise PluginError(
            f"{path.name}: plugin API {api!r} is not {PLUGIN_API_VERSION}"
        )
    kind = getattr(module, "PLUGIN_KIND", None)
    if kind not in KINDS:
        raise PluginError(f"{path.name}: PLUGIN_KIND must be one of {', '.join(KINDS)}")
    name = getattr(module, "PLUGIN_NAME", None)
    if not isinstance(name, str) or not NAME_PATTERN.match(name):
        raise PluginError(f"{path.name}: PLUGIN_NAME must match {NAME_PATTERN.pattern}")
    if kind == "exporter":
        handler = getattr(module, "export", None)
        if not callable(handler):
            raise PluginError(f"{path.name}: an exporter must define export(database, output)")
        return Plugin(name=name, kind=kind, api=api, path=path, export=handler)
    theme = getattr(module, "THEME", None)
    if not isinstance(theme, dict) or not theme:
        raise PluginError(f"{path.name}: a theme must declare a THEME mapping")
    return Plugin(name=name, kind=kind, api=api, path=path, theme=dict(theme))


def load_plugins(
    *, enabled: bool = True, directories: tuple[str | Path, ...] = ()
) -> PluginRegistry:
    """Load every valid plugin, collecting one sentence per refusal."""
    if not enabled or disabled():
        return PluginRegistry()
    exporters: dict[str, Plugin] = {}
    themes: dict[str, Plugin] = {}
    errors: list[str] = []
    index = 0
    for directory in plugin_directories(directories):
        if not directory.is_dir():
            continue
        for path in sorted(directory.glob("*.py")):
            if path.name.startswith("_"):
                continue
            if path.is_symlink() and not _inside(path, directory):
                errors.append(f"{path.name}: symlink points outside {directory}")
                continue
            index += 1
            try:
                plugin = _validate(path, _import(path, index))
            except PluginError as exc:
                errors.append(str(exc))
                continue
            target = exporters if plugin.kind == "exporter" else themes
            if plugin.name in target:
                errors.append(f"{path.name}: name {plugin.name!r} is already taken")
                continue
            target[plugin.name] = plugin
    return PluginRegistry(exporters=exporters, themes=themes, errors=tuple(errors))


def describe(registry: PluginRegistry) -> list[str]:
    """One line per loaded plugin, for `lumos plugins`."""
    lines = [f"export {name}  ({plugin.path.name})" for name, plugin in sorted(registry.exporters.items())]
    lines += [f"theme  {name}  ({plugin.path.name})" for name, plugin in sorted(registry.themes.items())]
    return lines