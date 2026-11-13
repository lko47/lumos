"""Render the Lumos TUI into a pyte screen and report raw escape traffic."""
from __future__ import annotations

import os
import pty
import re
import select
import struct
import fcntl
import sys
import termios
import time

import pyte

DB = sys.argv[1]
ROWS, COLS = 32, 110
ENV = dict(os.environ)
ENV["PYTHONPATH"] = "/home/user/.hermes/cache/scratch/lumos-review/src"
ENV["TERM"] = "xterm-256color"
ENV.pop("NO_COLOR", None)

master, slave = pty.openpty()
fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLS, 0, 0))
pid = os.fork()
if pid == 0:
    os.setsid()
    fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    os.dup2(slave, 0); os.dup2(slave, 1); os.dup2(slave, 2)
    os.execvpe(sys.executable, [sys.executable, "-m", "lumos", "tui", DB], ENV)

screen = pyte.Screen(COLS, ROWS)
stream = pyte.ByteStream(screen)
raw = bytearray()


def pump(seconds: float) -> None:
    end = time.time() + seconds
    while time.time() < end:
        r, _, _ = select.select([master], [], [], 0.05)
        if r:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                return
            if not chunk:
                return
            raw.extend(chunk)
            stream.feed(chunk)


pump(1.5)
for key in (b"j", b"j", b"e", b"v", b"j", b"m", b"j"):
    os.write(master, key)
    pump(0.7)
os.write(master, b"q")
pump(1.0)
os.waitpid(pid, 0)

print("=== screen (map view after keys moved to hosts/scans) ===")
for i, line in enumerate(screen.display, 1):
    print(f"{i:02d}|{line.rstrip()}")
print("=== raw control sequences emitted by lumos after curses init ===")
text = raw.decode("utf-8", "replace")
seqs = re.findall(r"\x1b(?:\[[0-9;?]*[ -/]*[@-~]|\][^\x07]*\x07|[@-_])", text)
from collections import Counter
for seq, n in Counter(seqs).most_common(12):
    print(repr(seq), n)
print("BEL chars:", text.count("\x07"), "  ESC chars:", text.count("\x1b"))
print("row 1 contains 'RED' or 'pwned':", "RED" in screen.display[0] or "pwned" in " ".join(screen.display))
print("\n".join(l for l in screen.display if "evil" in l.lower() or "RED" in l or "pwned" in l))
