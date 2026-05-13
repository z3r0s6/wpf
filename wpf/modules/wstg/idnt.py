"""WSTG-IDNT — Identity Management (5 tests). Manual checklist by default."""
from __future__ import annotations

from ..checklists import wstg_by_category
from ._base import manual_class_for

for _t in wstg_by_category("IDNT"):
    manual_class_for(_t["id"], _t.get("name", _t["id"]), "IDNT", severity="info")
