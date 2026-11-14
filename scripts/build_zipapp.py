"""Build dist/lumos.pyz and its SHA256SUMS.

The package is pure standard library, so a zipapp is a real distribution: one
file, no dependencies, runnable on any Python 3.10+ interpreter.
"""

from __future__ import annotations

import hashlib
import shutil
import tempfile
import zipapp
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ENTRY = "from lumos.cli import main\n\nraise SystemExit(main())\n"


def build(target: Path | None = None) -> tuple[Path, Path]:
    dist = ROOT / "dist"
    dist.mkdir(exist_ok=True)
    archive = target or dist / "lumos.pyz"
    with tempfile.TemporaryDirectory() as tmp:
        stage = Path(tmp) / "app"
        shutil.copytree(
            ROOT / "src" / "lumos",
            stage / "lumos",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"),
        )
        (stage / "__main__.py").write_text(ENTRY, encoding="utf-8")
        zipapp.create_archive(
            stage, target=archive, interpreter="/usr/bin/env python3", compressed=True
        )
    archive.chmod(0o755)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    sums = dist / "SHA256SUMS"
    sums.write_text(f"{digest}  {archive.name}\n", encoding="ascii")
    return archive, sums


if __name__ == "__main__":
    built, checksums = build()
    print(f"{built}  ({built.stat().st_size} bytes)")
    print(checksums.read_text(encoding="ascii").strip())
