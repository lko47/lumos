"""Small, curses-independent renderer for 2-by-4 Unicode braille cells."""

from __future__ import annotations


_BRAILLE_BASE = 0x2800
_DOT_BITS = (
    (0x01, 0x08),
    (0x02, 0x10),
    (0x04, 0x20),
    (0x40, 0x80),
)

# Dot cadence: traceroute is solid; alternate adds a parallel solid trace;
# inferred is dotted, and manual/imported edges use distinct dash lengths.
_STYLE_PATTERN = {
    "traceroute": (1, 0),
    "alternate": (1, 0),
    "inferred": (1, 2),
    "manual": (3, 2),
    "imported": (2, 3),
}


class BrailleCanvas:
    """Accumulate line segments in terminal-cell coordinates.

    Canvas dimensions are terminal cells; line coordinates are braille dots,
    so the drawable raster is ``width * 2`` by ``height * 4`` dots.
    Out-of-bounds dots are clipped.
    """

    def __init__(self, width: int, height: int) -> None:
        if width < 0 or height < 0:
            raise ValueError("braille canvas dimensions cannot be negative")
        self.width = width
        self.height = height
        self._cells = [[0 for _ in range(width)] for _ in range(height)]

    def set_dot(self, x: int, y: int) -> None:
        """Set a raster dot, ignoring coordinates outside the canvas."""
        if x < 0 or y < 0 or x >= self.width * 2 or y >= self.height * 4:
            return
        self._cells[y // 4][x // 2] |= _DOT_BITS[y % 4][x % 2]

    def draw_line(self, start: tuple[int, int], end: tuple[int, int], *, style: str = "traceroute") -> None:
        """Draw a clipped Bresenham segment using an edge-type dot pattern."""
        x0, y0 = start
        x1, y1 = end
        dx = abs(x1 - x0)
        sx = 1 if x0 < x1 else -1
        dy = -abs(y1 - y0)
        sy = 1 if y0 < y1 else -1
        error = dx + dy
        on, off = _STYLE_PATTERN.get(style, _STYLE_PATTERN["traceroute"])
        period = on + off
        step = 0
        last_step = max(dx, -dy)

        while True:
            if step == 0 or step == last_step or period == 0 or step % period < on:
                self.set_dot(x0, y0)
                if style == "alternate":
                    # A parallel dot trace differentiates alternate paths even
                    # in monochrome terminals without implying a different edge.
                    if dx >= -dy:
                        self.set_dot(x0, y0 + 1)
                    else:
                        self.set_dot(x0 + 1, y0)
            if x0 == x1 and y0 == y1:
                break
            twice = 2 * error
            if twice >= dy:
                error += dy
                x0 += sx
            if twice <= dx:
                error += dx
                y0 += sy
            step += 1

    def masks(self) -> tuple[tuple[int, ...], ...]:
        """Return the raw dot mask per terminal cell (0 when untouched)."""
        return tuple(tuple(row) for row in self._cells)

    def render(self) -> tuple[str, ...]:
        """Return one Unicode braille character per terminal cell."""
        return tuple(
            "".join(chr(_BRAILLE_BASE + mask) for mask in row)
            for row in self._cells
        )
