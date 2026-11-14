"""Render a real TUI session to SVG, from the generated demo engagement.

A screenshot in this repository has to be reproducible and free of somebody's
network, so it is produced from `lumos demo` data by driving the interface in a
pseudo-terminal and turning the resulting character grid into vector text.

Requires `pyte` (a development dependency, not a runtime one):

    python3 -m venv /tmp/shot && /tmp/shot/bin/pip install pyte
    PYTHONPATH=src /tmp/shot/bin/python scripts/make_screenshot.py \
        --out docs/screenshots/map.svg

Nothing else is written: the demo database lives in a temporary directory and is
deleted afterwards.
"""

from __future__ import annotations

import argparse
import fcntl
import os
import pty
import select
import struct
import subprocess
import sys
import tempfile
import termios
import time
from pathlib import Path

try:
    import pyte
except ImportError:  # pragma: no cover - development tool
    raise SystemExit("scripts/make_screenshot.py needs pyte: pip install pyte")

ROOT = Path(__file__).resolve().parents[1]
NAMED = {
    "black": "#1c1c1c", "red": "#d75f5f", "green": "#87af5f", "brown": "#d7af5f",
    "yellow": "#d7af5f", "blue": "#5f87af", "magenta": "#af87af", "cyan": "#5fafaf",
    "white": "#d0d0d0", "default": None,
}


def _drain(master: int, screen: pyte.Screen, stream: pyte.Stream, seconds: float) -> None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        ready, _, _ = select.select([master], [], [], 0.05)
        if master in ready:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                return
            if not chunk:
                return
            stream.feed(chunk.decode("utf-8", "replace"))


def _colour(value: object, fallback: str) -> str:
    """pyte reports 256-colour cells as bare hex ("ff87ff"), not as "#ff87ff"."""
    text = str(value)
    if text.startswith("#"):
        return text
    if len(text) == 6 and all(character in "0123456789abcdef" for character in text.lower()):
        return f"#{text}"
    named = NAMED.get(text)
    return named or fallback


def _svg(screen: pyte.Screen, cols: int, rows: int, cell_w: float, cell_h: float) -> str:
    width, height = cols * cell_w, rows * cell_h
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}"'
        f' viewBox="0 0 {width:.0f} {height:.0f}" font-family="ui-monospace, \'DejaVu Sans Mono\','
        ' Menlo, monospace" font-size="13">',
        f'<rect width="{width:.0f}" height="{height:.0f}" fill="#12121a"/>',
    ]
    for row in range(rows):
        line = screen.buffer[row]
        # Group horizontally adjacent cells that share a background, so the file
        # stays small without losing colour fidelity.
        runs: list[tuple[int, int, str]] = []
        for col in range(cols):
            cell = line[col]
            background = _colour(cell.bg, "#12121a")
            if runs and runs[-1][2] == background and runs[-1][1] == col - 1:
                runs[-1] = (runs[-1][0], col, background)
            else:
                runs.append((col, col, background))
        for start, end, background in runs:
            if background == "#12121a":
                continue
            parts.append(
                f'<rect x="{start * cell_w:.2f}" y="{row * cell_h:.2f}"'
                f' width="{(end - start + 1) * cell_w:.2f}" height="{cell_h:.2f}"'
                f' fill="{background}"/>'
            )
        col = 0
        while col < cols:
            cell = line[col]
            if not cell.data.strip():
                col += 1
                continue
            start, text, fg, bold = col, "", _colour(cell.fg, "#d0d0d0"), cell.bold
            while col < cols:
                current = line[col]
                if (not current.data.strip() or _colour(current.fg, "#d0d0d0") != fg
                        or current.bold != bold):
                    break
                text += current.data
                col += 1
            weight = ' font-weight="bold"' if bold else ""
            parts.append(
                f'<text x="{start * cell_w:.2f}" y="{row * cell_h + cell_h * 0.78:.2f}"'
                f' fill="{fg}"{weight} xml:space="preserve">{_escape(text)}</text>'
            )
    parts.append("</svg>")
    return "".join(parts)


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def capture(database: Path, cols: int, rows: int, wait: float, keys: str = "") -> pyte.Screen:
    screen = pyte.Screen(cols, rows)
    stream = pyte.Stream(screen)
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
    env = dict(os.environ, TERM="xterm-256color", LINES=str(rows), COLUMNS=str(cols),
               PYTHONPATH=str(ROOT / "src"))
    proc = subprocess.Popen(
        [sys.executable, "-m", "lumos", str(database)],
        stdin=slave, stdout=slave, stderr=slave, env=env, close_fds=True,
    )
    os.close(slave)
    try:
        _drain(master, screen, stream, wait)
        for key in keys:
            os.write(master, key.encode())
            _drain(master, screen, stream, 0.8)
        _drain(master, screen, stream, 0.4)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover
            proc.kill()
        os.close(master)
    return screen


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, default=ROOT / "docs" / "screenshots" / "map.svg")
    parser.add_argument("--cols", type=int, default=128)
    parser.add_argument("--rows", type=int, default=36)
    parser.add_argument("--wait", type=float, default=3.0)
    parser.add_argument("--keys", default="", help="keys to send after the first frame")
    parser.add_argument("--database", type=Path, default=None,
                        help="engagement to render (default: a fresh demo in a temp dir)")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory() as tmp:
        database = args.database
        if database is None:
            database = Path(tmp) / "demo.sqlite"
            from lumos.cli import main as lumos_main  # noqa: PLC0415 - keeps --help fast
            argv = sys.argv
            sys.argv = ["lumos", "demo", str(database)]
            try:
                lumos_main()
            finally:
                sys.argv = argv
        screen = capture(database, args.cols, args.rows, args.wait, args.keys)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(_svg(screen, args.cols, args.rows, 7.4, 16.0), encoding="utf-8")
    print(f"wrote {args.out} ({args.out.stat().st_size} bytes, {args.cols}x{args.rows})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
