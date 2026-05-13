"""WSTG-BUSL — Business Logic (9 tests). All manual — these are the WSTG tests
that require knowing the application's workflow (price tampering, parameter
manipulation, file upload semantics, etc.)."""
from __future__ import annotations

from ..checklists import wstg_by_category
from ._base import manual_class_for

for _t in wstg_by_category("BUSL"):
    manual_class_for(_t["id"], _t.get("name", _t["id"]), "BUSL", severity="info")
