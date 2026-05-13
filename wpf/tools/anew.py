"""anew — append-only dedup utility. Used as a plumbing wrapper."""
from __future__ import annotations

from pathlib import Path
from typing import Iterable


def dedup_into(file: Path, lines: Iterable[str]) -> list[str]:
    """Append new lines to file, return newly-added ones. Pure-python; no binary."""
    existing = set()
    if file.exists():
        existing = set(file.read_text(encoding="utf-8").splitlines())
    new = []
    with file.open("a", encoding="utf-8") as fh:
        for ln in lines:
            ln = ln.strip()
            if ln and ln not in existing:
                fh.write(ln + "\n")
                existing.add(ln)
                new.append(ln)
    return new
