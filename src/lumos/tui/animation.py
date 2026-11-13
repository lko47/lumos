"""Time-driven glyphs for the topology view: packet dots, ripples, blink, pulse.

Every function here is pure.  Callers pass ``now`` (a monotonic clock reading),
so tests step time instead of sleeping and a frame is a function of its inputs.

The motion is deliberately slow and sparse: one dot per measured link, three
ripple rings, one pulse column per second.  Nothing here reads curses, the
database or the network.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

# Scheduling -----------------------------------------------------------------
TICK_SECONDS = 0.25
IDLE_SECONDS = 1.0

# Packet dots along a measured link ------------------------------------------
FLOW_PERIOD_SECONDS = 3.5
FLOW_DOTS_PER_EDGE = 1
FLOW_GLYPH = "·"
FLOW_GLYPH_ASCII = "*"
PHASE_BUCKETS = 997

# Discovery ripple -----------------------------------------------------------
RIPPLE_SECONDS = 0.6
RIPPLE_RINGS = 3
RIPPLE_MAX_ACTIVE = 64
RIPPLE_STORM_LIMIT = 32
RIPPLE_GLYPHS = ("▓", "▒", "░")
RIPPLE_GLYPHS_ASCII = ("#", "+", ".")

# Confirm-button blink -------------------------------------------------------
BLINK_ON_SECONDS = 0.6
BLINK_OFF_SECONDS = 0.4
BLINK_CYCLES = 5

# Liveness strip -------------------------------------------------------------
PULSE_WIDTH = 16
PULSE_GLYPHS = "▁▂▃▄▅▆▇█"
PULSE_GLYPHS_ASCII = "_.-=+*#"


@dataclass(frozen=True)
class Ripple:
    """One node's discovery ripple: where it started and when."""

    x: int
    y: int
    started_at: float


def tick_timeout(animating: bool) -> int:
    """Milliseconds to wait for input, given whether something is moving."""
    return int(TICK_SECONDS * 1000) if animating else int(IDLE_SECONDS * 1000)


def phase_for(key: str) -> float:
    """Deterministic 0..1 phase from an identifier, stable across runs.

    Avoids ``hash()``, which is salted per process, so two frames of the same
    graph animate identically and golden tests stay reproducible.
    """
    total = 0
    for index, char in enumerate(key):
        total += (index + 1) * ord(char)
    return (total % PHASE_BUCKETS) / PHASE_BUCKETS


def _progress(now: float, phase: float) -> float:
    """Fraction of one traverse at ``now``, offset by ``phase``."""
    return (now / FLOW_PERIOD_SECONDS + phase) % 1.0


def flow_position(
    start: tuple[int, int],
    end: tuple[int, int],
    phase: float,
    now: float,
) -> tuple[int, int]:
    """The cell a packet dot occupies on the segment ``start`` → ``end``."""
    fraction = _progress(now, phase)
    x = round(start[0] + (end[0] - start[0]) * fraction)
    y = round(start[1] + (end[1] - start[1]) * fraction)
    return (x, y)


def flow_visible(
    start: tuple[int, int],
    end: tuple[int, int],
    now: float,
) -> bool:
    """True when the link is long enough to put a dot on without clutter."""
    return abs(end[0] - start[0]) + abs(end[1] - start[1]) >= 2


def ripple_radius(started_at: float, now: float) -> int:
    """Current ring index (0-based) of a ripple, or -1 when it has finished."""
    elapsed = now - started_at
    if elapsed < 0:
        return -1
    ring_period = RIPPLE_SECONDS / RIPPLE_RINGS
    radius = int(elapsed / ring_period)
    return radius if radius < RIPPLE_RINGS else -1


def ripple_cells(center: tuple[int, int], radius: int) -> tuple[tuple[int, int], ...]:
    """Cells forming the square ring at ``radius`` around ``center``."""
    if radius < 0:
        return ()
    cx, cy = center
    cells: list[tuple[int, int]] = []
    for offset in range(-radius, radius + 1):
        cells.append((cx + offset, cy - radius))
        cells.append((cx + offset, cy + radius))
    for offset in range(-radius + 1, radius):
        cells.append((cx - radius, cy + offset))
        cells.append((cx + radius, cy + offset))
    return tuple(cells)


def ripple_glyph(radius: int, unicode_ok: bool = True) -> str:
    """Glyph for a ring, fading outward."""
    table = RIPPLE_GLYPHS if unicode_ok else RIPPLE_GLYPHS_ASCII
    return table[max(0, min(radius, len(table) - 1))]


def storm(added: int) -> bool:
    """True when a snapshot gained too many nodes at once to animate them all.

    A 500-host sweep should read as a result, not as a seizure.
    """
    return added > RIPPLE_STORM_LIMIT


def blink_visible(primed_at: float, now: float) -> bool:
    """Confirm-button blink state once the operator primes the checkbox.

    Blinks for a bounded number of cycles, then stays solid: an endlessly
    blinking control is an accessibility problem, not a signal.
    """
    elapsed = now - primed_at
    if elapsed < 0:
        return True
    cycle = BLINK_ON_SECONDS + BLINK_OFF_SECONDS
    if elapsed >= cycle * BLINK_CYCLES:
        return True
    return (elapsed % cycle) < BLINK_ON_SECONDS


def pulse_row(samples: Sequence[int], width: int = PULSE_WIDTH, ascii_ok: bool = False) -> str:
    """Render recent event counts as a waveform, newest sample on the right.

    ``samples`` are deltas of a real counter (frames, hosts, packets, XML
    bytes).  A flat line means nothing happened; the column still advances once
    a second, which is what tells the operator the interface is alive.
    """
    glyphs = PULSE_GLYPHS_ASCII if ascii_ok else PULSE_GLYPHS
    window = list(samples)[-width:]
    if not window:
        return glyphs[0] * width
    peak = max(window) or 1
    cells = [glyphs[min(len(glyphs) - 1, int(level * (len(glyphs) - 1) / peak))] for level in window]
    # The newest column is always drawn one notch high, so a completely idle
    # interface still shows the tick advancing once a second.
    if cells:
        cells[-1] = glyphs[max(1, glyphs.index(cells[-1]))]
    return "".join(cells).rjust(width, glyphs[0])


def level_for(delta: int, peak: int) -> int:
    """Index into the waveform glyph table for one delta."""
    if peak <= 0:
        return 0
    return max(0, min(len(PULSE_GLYPHS) - 1, int(delta * (len(PULSE_GLYPHS) - 1) / peak)))


def active_ripples(ripples: Iterable[tuple[str, float]], now: float) -> int:
    """Count ripples that are still visible at ``now``."""
    return sum(1 for _node_id, started_at in ripples if ripple_radius(started_at, now) >= 0)