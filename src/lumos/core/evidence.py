"""Evidence classes shared by the TUI and the reports.

A link's class answers one question: how was this known? Only ``inferred``
classes may be drawn as dots or dashes, so a guess can never borrow the solid
line that means a measurement.
"""

from __future__ import annotations

CLASSES = ("local", "observed", "alternate", "likely", "weak", "manual")

LIKELY_THRESHOLD = 0.6

# (stroke width, dash array, colour) per class; reports use these directly.
SVG_STYLE = {
    "local": (3.0, "", "#f2f2f2"),
    "observed": (2.0, "", "#7fd1ff"),
    "alternate": (2.0, "", "#ffd166"),
    "manual": (2.0, "", "#ff79c6"),
    "likely": (1.6, "3 2", "#8ab4ff"),
    "weak": (1.0, "1 5", "#7f8ea3"),
}


def classify(edge_type: str, confidence: float) -> str:
    """Map a stored link to its evidence class."""
    if edge_type == "local":
        return "local"
    if edge_type == "manual":
        return "manual"
    if edge_type == "alternate":
        return "alternate"
    if edge_type == "inferred":
        return "likely" if confidence >= LIKELY_THRESHOLD else "weak"
    return "observed"


def is_dotted(edge_type: str, confidence: float) -> bool:
    return classify(edge_type, confidence) in {"likely", "weak"}
