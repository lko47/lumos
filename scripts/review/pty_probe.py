"""PTY robustness probe: resize tiny/huge, ASCII/NO_COLOR, SIGTERM restore."""
from __future__ import annotations

import fcntl
import os
from pathlib import Path
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time

DB = sys.argv[1]
MODE = sys.argv[2] if len(sys.argv) > 2 else "sigterm"
ENV = dict(os.environ)
ENV["PYTHONPATH"] = str(Path(__file__).resolve().parents[2] / "src")
ENV.pop("LUMOS_DB", None)
ENV.setdefault("TERM", "xterm-256color")
ENV["TERM"] = ENV.get("TERM") or "xterm-256color"
ENV["TERM"] = "xterm-256color"
if MODE == "ascii":
    ENV["LUMOS_ASCII"] = "1"
if MODE == "nocolor":
    ENV["NO_COLOR"] = "1"

master, slave = pty.openpty()
before = termios.tcgetattr(slave)
def setsize(fd, rows, cols):
    fcntl.ioctl(fd, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
setsize(slave, 10, 30)
proc = subprocess.Popen(
    [sys.executable, "-m", "lumos", "tui", DB],
    stdin=slave, stdout=slave, stderr=slave, env=ENV, start_new_session=True, close_fds=True,
)
os.close(slave)
out = bytearray()
def pump(seconds):
    end = time.time() + seconds
    while time.time() < end:
        r, _, _ = select.select([master], [], [], 0.1)
        if r:
            try:
                chunk = os.read(master, 65536)
            except OSError:
                return False
            if not chunk:
                return False
            out.extend(chunk)
    return True

pump(2.0)
setsize(master, 4, 12); pump(1.0)          # absurdly small
os.write(master, b"m"); pump(0.4)
setsize(master, 60, 200); pump(1.0)        # huge
os.write(master, b"v"); pump(0.4)
os.write(master, b"s"); pump(0.4)
setsize(master, 32, 110); pump(0.6)
if MODE == "sigterm":
    proc.send_signal(signal.SIGTERM)
elif MODE == "sigint":
    proc.send_signal(signal.SIGINT)
elif MODE == "crash":
    # force an internal error path: close the database underneath the app
    os.rename(DB, DB + ".moved")
    pump(2.5)
else:
    os.write(master, b"q")
pump(2.0)
try:
    rc = proc.wait(timeout=5)
except subprocess.TimeoutExpired:
    proc.kill(); rc = "KILLED"
time.sleep(0.2)
try:
    after = termios.tcgetattr(master)
except termios.error:
    after = None
text = out.decode("utf-8", "replace")
plain = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07]*\x07|\x1b[@-_]", "", text)
print(f"MODE={MODE} rc={rc} bytes={len(out)}")
print("termios restored:", after is not None and after[3] == before[3] and after[0] == before[0] and after[1] == before[1])
print("ECHO restored:", bool((after[3] if after else 0) & termios.ECHO), " ICANON:", bool((after[3] if after else 0) & termios.ICANON))
print("traceback in output:", "Traceback (most recent call last)" in plain)
print("exception text:", "Exception" in plain or "Error:" in plain)
print("alt-screen left behind:", "\x1b[?1049h" in text and not text.rstrip().endswith("\x1b[?1049l"))
tail = [line for line in plain.splitlines() if line.strip()][-4:]
print("last lines:", tail)
