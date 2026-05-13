"""WSTG-ATHZ — Authorization (4 tests). Manual checklist by default — IDOR and
privilege-escalation checks need session context; see modules/bbb/ch10_idor.py
for a guided runner."""
from __future__ import annotations

from ..checklists import wstg_by_category
from ._base import manual_class_for

for _t in wstg_by_category("ATHZ"):
    manual_class_for(_t["id"], _t.get("name", _t["id"]), "ATHZ", severity="info")
