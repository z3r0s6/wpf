"""Engagement metadata loader. Thin wrapper around Scope's engagement block."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from .scope import Scope


@dataclass
class EngagementContext:
    name: str
    type: str               # bug_bounty | pentest | lab
    authorized_by: str = ""
    client: str = ""
    start: str = ""
    end: str = ""

    @classmethod
    def from_scope(cls, scope: Scope) -> "EngagementContext":
        e = scope.engagement
        return cls(name=e.name, type=e.type, authorized_by=e.authorized_by,
                   start=e.start, end=e.end)

    @classmethod
    def make(cls, name: str, type_: str = "lab", authorized_by: str = "") -> "EngagementContext":
        today = date.today().isoformat()
        return cls(name=name, type=type_, authorized_by=authorized_by, start=today)
