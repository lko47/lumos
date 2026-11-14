"""Scan profiles as data: a JSON file the operator can edit.

The built-in presets stay in the code as the fallback; a profiles file adds new
names and can never redefine a built-in one, so a config file cannot quietly
change what "service" means. Every profile's options are parsed with
``shlex`` and checked against the same refusals the runner applies, because a
profile is a command line wearing a name.
"""

from __future__ import annotations

import json
import os
import shlex
from dataclasses import dataclass
from pathlib import Path

MAX_PROFILES = 24
MAX_OPTIONS_CHARS = 400
NAME_CHARS = 32
# Anything that writes an extra artefact, reads targets from a file, or runs
# scripts is refused: Lumos has to own the input and the output stream.
REFUSED_FLAGS = ("-oX", "-oA", "-oN", "-oG", "-iL", "-iR", "--script", "--script-args")


class ProfileError(ValueError):
    """A profile that will not load, with the reason in the sentence."""


@dataclass(frozen=True)
class Profile:
    name: str
    options: str
    description: str = ""


def profile_path() -> Path:
    explicit = os.environ.get("LUMOS_PROFILES", "").strip()
    if explicit:
        return Path(explicit).expanduser()
    config = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(config) / "lumos" / "profiles.json"


def _validate(name: object, options: object) -> Profile:
    text_name = str(name or "").strip()
    if not text_name or len(text_name) > NAME_CHARS or not text_name.isprintable():
        raise ProfileError(f"profile name {text_name!r} must be 1-{NAME_CHARS} printable characters")
    text = str(options or "").strip()
    if len(text) > MAX_OPTIONS_CHARS:
        raise ProfileError(f"profile {text_name!r} options exceed {MAX_OPTIONS_CHARS} characters")
    try:
        tokens = shlex.split(text)
    except ValueError as exc:
        raise ProfileError(f"profile {text_name!r} has unbalanced quoting: {exc}") from exc
    for token in tokens:
        flag = token.split("=", 1)[0]
        if flag in REFUSED_FLAGS:
            raise ProfileError(
                f"profile {text_name!r} uses {flag}, which Lumos does not allow"
                " (it would write a second artefact or read targets behind the scope guard)"
            )
    return Profile(name=text_name, options=" ".join(tokens))


def load_profiles(path: str | Path | None = None) -> dict[str, Profile]:
    """Read the profiles file; a missing file is not an error."""
    target = Path(path) if path is not None else profile_path()
    if not target.is_file():
        return {}
    try:
        raw = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ProfileError(f"{target} is not readable JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise ProfileError(f"{target} must contain an object of name -> options")
    entries = raw.get("profiles", raw)
    if not isinstance(entries, dict) or len(entries) > MAX_PROFILES:
        raise ProfileError(f"{target} must hold at most {MAX_PROFILES} profiles")
    profiles: dict[str, Profile] = {}
    for name, value in entries.items():
        if name == "profiles":
            continue
        options = value.get("options", "") if isinstance(value, dict) else value
        description = value.get("description", "") if isinstance(value, dict) else ""
        profile = _validate(name, options)
        profile = Profile(profile.name, profile.options, str(description)[:120])
        profiles[profile.name] = profile
    return profiles


def merged(builtin: dict[str, str], custom: dict[str, Profile]) -> dict[str, Profile]:
    """Built-ins plus custom profiles; a custom may not take a built-in name."""
    result = {name: Profile(name, options) for name, options in builtin.items()}
    for name, profile in custom.items():
        if name in builtin:
            raise ProfileError(
                f"profile {name!r} redefines a built-in preset; choose another name"
            )
        result[name] = profile
    return result


def choices(builtin: dict[str, str]) -> tuple[str, ...]:
    """Preset names in a stable order, with any user profiles after them."""
    try:
        custom = load_profiles()
    except ProfileError:
        custom = {}
    names = list(builtin)
    names += sorted(name for name in custom if name not in builtin)
    return tuple(names)


def options_for(builtin: dict[str, str], name: str, extra: str = "") -> str:
    """The options string for a preset or profile; unknown names are an error."""
    resolved = merged(builtin, load_profiles())
    profile = resolved.get(name)
    if profile is None:
        raise ProfileError(f"unknown scan profile {name!r}")
    return f"{profile.options} {extra}".strip()