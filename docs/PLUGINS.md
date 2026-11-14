# Plugins

Lumos ships a small, versioned plugin surface: **exporters** and **themes**. There is no hook that can change how a scan runs or what the scope guard allows.

## Where plugins come from

Only directories you name:

1. `LUMOS_PLUGIN_PATH` — a path-separated list.
2. `$XDG_CONFIG_HOME/lumos/plugins` (default `~/.config/lumos/plugins`).

`lumos --no-plugins ...` or `LUMOS_NO_PLUGINS=1` disables the surface entirely. A plugin file that is a symlink pointing outside its directory is ignored, not followed.

**A plugin is arbitrary Python and gets your privileges.** Importing it runs its code; the loader only validates its declarations. Install plugins the way you install software: from a source you trust.

## Writing an exporter

```python
PLUGIN_API = 1
PLUGIN_KIND = "exporter"
PLUGIN_NAME = "kml"          # lowercase, digits, '-' and '_', up to 32 chars

def export(database: str, output: str) -> str:
    ...                      # open the database read-only, write output
    return "wrote N placemarks"   # one line shown to the operator
```

Run it with:

```sh
lumos report plugin ENGAGEMENT.sqlite hosts.kml --name kml
```

The loader checks the file wrote something before reporting success. A plugin that returns normally without writing is reported as a failure rather than silently leaving no file.

## Writing a theme

```python
PLUGIN_API = 1
PLUGIN_KIND = "theme"
PLUGIN_NAME = "sunset"

THEME = {
    "title": {"fg": 208, "fg16": 3, "attr": 1},   # xterm-256 index, 16-colour index, curses attr
    "device": {"fg": 250, "fg16": 7},
}
```

Plugin palettes are merged at startup; `t` cycles through them with the built-ins. A plugin may not replace a built-in theme — a colliding name is ignored, so a plugin cannot quietly change how the interface looks.

Semantic tokens are the ones the interface actually asks for (`title`, `border`, `device`, `zone`, `root`, `link_observed`, `link_inferred`, `warning`, `error`, `status`). Unknown tokens are ignored; a partial palette inherits the built-in default for the rest.

## What gets refused, and what you see

Every refusal is one sentence, per file, and the other plugins still load:

| Refusal | Message |
| --- | --- |
| No `PLUGIN_API` | `no PLUGIN_API version` |
| Wrong version | `plugin API 99 is not 1` |
| Unknown `PLUGIN_KIND` | `PLUGIN_KIND must be one of exporter, theme` |
| Bad `PLUGIN_NAME` | `PLUGIN_NAME must match ^[a-z0-9][a-z0-9_-]{0,31}$` |
| Exporter without `export()` | `an exporter must define export(database, output)` |
| Import raises | `failed while loading: <the exception>` |
| Duplicate name | `name 'x' is already taken` |

`lumos plugins` prints what would load and every refusal, and exits non-zero if anything was skipped.
