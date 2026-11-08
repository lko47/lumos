"""Sanitize untrusted text before storage or terminal presentation."""

from __future__ import annotations

import re
import unicodedata

_ANSI_ESCAPE = re.compile(
    r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\)|[@-_])"
)


def sanitize_text(value: object, *, max_chars: int = 4096) -> str:
    """Strip terminal escape/control sequences and cap untrusted text length."""
    text = str(value) if value is not None else ""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = _ANSI_ESCAPE.sub("", text)
    safe = []
    for char in text:
        category = unicodedata.category(char)
        if char in "\n\t" or category not in ("Cc", "Cf", "Cs"):
            safe.append(char)
    return "".join(safe)[: max(0, max_chars)]
