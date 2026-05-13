"""Load the embedded JSON checklists (WSTG + BBB)."""
from __future__ import annotations

import json
from functools import lru_cache

from ..core.config import PKG_DATA


@lru_cache(maxsize=1)
def wstg() -> dict:
    return json.loads((PKG_DATA / "wstg_checklist.json").read_text(encoding="utf-8"))


@lru_cache(maxsize=1)
def bbbootcamp() -> dict:
    return json.loads((PKG_DATA / "bbbootcamp_workflows.json").read_text(encoding="utf-8"))


def wstg_test(test_id: str) -> dict | None:
    test_id = test_id.upper().replace("_", "-")
    for t in wstg().get("tests", []):
        if t.get("id", "").upper() == test_id:
            return t
    return None


def wstg_by_category(code: str) -> list[dict]:
    code = code.upper()
    return [t for t in wstg().get("tests", []) if t.get("category", "").upper() == code]


def bbb_chapters() -> list[dict]:
    return bbbootcamp().get("chapters", [])


def bbb_chapter(num: int | str) -> dict | None:
    target = str(num).lstrip("ch")
    for ch in bbb_chapters():
        if str(ch.get("chapter_number")) == target:
            return ch
    return None
