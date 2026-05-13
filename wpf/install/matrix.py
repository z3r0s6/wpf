"""Load the install matrix produced from the tooling inventory."""
from __future__ import annotations

import json
from pathlib import Path

from ..core.config import PKG_DATA


def load_install_matrix() -> dict[str, dict[str, str]]:
    """Return {tool_name: {method, command, binary_check, post_install}}."""
    p = PKG_DATA / "install_matrix.json"
    return json.loads(p.read_text(encoding="utf-8"))


def load_tooling_inventory() -> list[dict[str, str]]:
    p = PKG_DATA / "tooling_inventory.json"
    raw = json.loads(p.read_text(encoding="utf-8"))
    # Some inventories wrap under "tools" — handle both shapes.
    if isinstance(raw, dict) and "tools" in raw:
        return raw["tools"]
    return raw


def categorize() -> dict[str, list[str]]:
    """Bucket tools by category for display in the doctor table."""
    cats: dict[str, list[str]] = {}
    for entry in load_tooling_inventory():
        cat = entry.get("category", "uncategorized")
        cats.setdefault(cat, []).append(entry.get("name", ""))
    return cats
