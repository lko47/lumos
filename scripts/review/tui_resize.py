"""Resize probe: tiny -> normal -> huge, dumped through pyte."""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import pty
import select
import struct
import sys
import termios
import time

import pyte

DB = sys.argv[1]
ENV = dict(os.environ)
ENV["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
ENV["TERM"] = "xterm-256color"


def setsize(fd, rows, cols):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))


master, slave = pty.openpty()
setsize(slave, 32, 110)
pid = os.fork()
if pid == 0:
    os.setsid(); fcntl.ioctl(slave, termios.TIOCSCTTY, 0)
    os.dup2(slave, 0); os.dup2(slave, 1); os.dup2(slave, 2)
    os.execvpe(sys.executable, [sys.executable, "-m", "lumos", "tui", DB], ENV)

screen = pyte.Screen(110, 32)
stream = pyte.ByteStream(screen)
raw = bytearray()


def pump(seconds):
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
            raw.extend(chunk); stream.feed(chunk)


def dump(label):
    print(f"--- {label}: {screen.columns}x{screen.lines} ---")
    print("\n".join(line.rstrip() for line in screen.display))


pump(1.5); dump("start 110x32")
for rows, cols in ((4, 12), (3, 8)):
    setsize(master, rows, cols); screen.resize(rows, cols); pump(1.2)
    print(f"resized to {cols}x{rows}: alive={os.waitpid(pid, os.WNOHANG) == (0, 0)}")
    dump(f"after {cols}x{rows}")
setsize(master, 32, 110); screen.resize(32, 110); pump(1.5); dump("back to 110x32")
setsize(master, 60, 200); screen.resize(60, 200); pump(1.5); dump("huge 200x60")
os.write(master, b"q"); pump(0.8)
text = raw.decode("utf-8", "replace")
print("traceback:", "Traceback (most recent call last)" in text)
print("BEL:", text.count("\x07"))
