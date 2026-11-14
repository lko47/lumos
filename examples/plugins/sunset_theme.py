"""Example Lumos theme plugin: warm amber on near-black.

Copy into ``~/.config/lumos/plugins/`` and press ``t`` in the interface until
"sunset" appears in the status bar.
"""

PLUGIN_API = 1
PLUGIN_KIND = "theme"
PLUGIN_NAME = "sunset"

THEME = {
    "title": {"fg": 208, "fg16": 3, "attr": 1},
    "border": {"fg": 130, "fg16": 3},
    "device": {"fg": 250, "fg16": 7},
    "zone": {"fg": 173, "fg16": 3},
    "root": {"fg": 215, "fg16": 3, "attr": 1},
    "link_observed": {"fg": 252, "fg16": 7},
    "link_inferred": {"fg": 137, "fg16": 3},
    "warning": {"fg": 214, "fg16": 3},
    "error": {"fg": 203, "fg16": 1},
    "status": {"fg": 247, "fg16": 7},
}
