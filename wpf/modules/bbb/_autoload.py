"""Auto-register manual-stub chapters for any BBB chapter that doesn't have a runner."""
from __future__ import annotations

from ..checklists import bbb_chapters
from ._shared import REGISTRY, manual_chapter


_IMPLEMENTED_NUMS = {5, 6, 7, 8, 9, 10, 11, 13, 14, 15, 16, 20, 21, 24}

for ch in bbb_chapters():
    num = int(ch.get("chapter_number") or 0)
    if num and num not in _IMPLEMENTED_NUMS:
        slug = (ch.get("title") or "ch{n}".format(n=num)).lower()
        slug = "".join(c if c.isalnum() else "_" for c in slug).strip("_")[:40]
        key = f"ch{num:02d}_{slug}"
        if key not in REGISTRY:
            manual_chapter(num, key, ch.get("title", ""))
