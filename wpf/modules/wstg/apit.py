"""WSTG-APIT — API Testing (1 test, GraphQL). Manual checklist."""
from __future__ import annotations

from ..checklists import wstg_by_category
from ._base import manual_class_for

for _t in wstg_by_category("APIT"):
    manual_class_for(_t["id"], _t.get("name", _t["id"]), "APIT", severity="info")
