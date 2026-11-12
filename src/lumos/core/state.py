"""Small, non-secret local state: which engagements were opened last.

Kept out of the engagement database on purpose - it describes this user's
machine, not the engagement, and losing it must never lose evidence.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

MAX_RECENT = 10


def state_dir() -> Path:
    """Return the per-user state directory, honouring XDG_STATE_HOME."""
    root = os.environ.get("XDG_STATE_HOME", "").strip()
    base = Path(root).expanduser() if root else Path.home() / ".local" / "state"
    return base / "lumos"


def state_path() -> Path:
    return state_dir() / "state.json"


def _read() -> dict:
    path = state_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"recent": []}
    if not isinstance(data, dict) or not isinstance(data.get("recent"), list):
        return {"recent": []}
    entries = []
    for item in data["recent"]:
        if not isinstance(item, dict):
            continue
        path_value = str(item.get("path") or "").strip()
        if not path_value:
            continue
        entries.append(
            {
                "path": path_value,
                "name": str(item.get("name") or "")[:128],
                "opened_at": str(item.get("opened_at") or ""),
            }
        )
    return {"recent": entries[:MAX_RECENT]}


def recent_engagements() -> list[dict]:
    """Recently opened databases, newest first, missing files flagged."""
    entries = _read()["recent"]
    result = []
    for item in entries:
        path = Path(item["path"]).expanduser()
        result.append(
            {
                "path": str(path),
                "name": item["name"] or path.stem,
                "opened_at": item["opened_at"],
                "exists": path.is_file(),
            }
        )
    return result


def _write(data: dict) -> None:
    directory = state_dir()
    directory.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(directory, 0o700)
    except OSError:
        pass
    handle, temporary = tempfile.mkstemp(dir=str(directory), prefix=".state-", suffix=".json")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            json.dump(data, stream, indent=2, sort_keys=True)
        os.chmod(temporary, 0o600)
        os.replace(temporary, state_path())
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def remember_engagement(path: str | Path, name: str = "") -> None:
    """Move a database to the top of the recent list; ignore missing files."""
    resolved = Path(path).expanduser().absolute()
    if not resolved.is_file():
        return
    from .database import utc_now

    recent = [item for item in _read()["recent"] if Path(item["path"]).expanduser().absolute() != resolved]
    recent.insert(
        0,
        {"path": str(resolved), "name": name or resolved.stem, "opened_at": utc_now()},
    )
    _write({"recent": recent[:MAX_RECENT]})


def forget_engagement(path: str | Path) -> None:
    resolved = Path(path).expanduser().absolute()
    recent = [item for item in _read()["recent"] if Path(item["path"]).expanduser().absolute() != resolved]
    _write({"recent": recent})
