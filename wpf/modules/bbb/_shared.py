"""Shared base for BBB chapter workflows."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Type

from ...core.finding import Finding
from ...core.scope import Scope
from ..checklists import bbb_chapter, bbb_chapters

REGISTRY: dict[str, Type["BBBWorkflow"]] = {}


def register(cls: Type["BBBWorkflow"]) -> Type["BBBWorkflow"]:
    REGISTRY[cls.key] = cls
    return cls


class BBBWorkflow(ABC):
    key: str = ""             # e.g. "ch06_xss"
    chapter_number: int = 0
    title: str = ""

    @classmethod
    def meta(cls) -> dict:
        return bbb_chapter(cls.chapter_number) or {}

    @abstractmethod
    async def run(self, target: str, *, scope: Scope, **kwargs) -> list[Finding]:
        ...


class ManualChapter(BBBWorkflow):
    """Emit a stub finding wrapping the chapter's methodology + tools list."""

    async def run(self, target: str, *, scope: Scope, **kwargs) -> list[Finding]:
        meta = self.meta()
        return [Finding(
            code=self.key.upper(),
            title=f"BBB {meta.get('title', self.title)} — methodology checklist",
            severity="info",
            confidence="low",
            asset=target,
            description=meta.get("vulnerability_class") or meta.get("topic")
                       or meta.get("recon_stage") or self.title,
            recommendation="Follow the methodology steps. Update this finding with evidence per step.",
            bbb_chapter=self.key,
            evidence={
                "methodology":   meta.get("methodology", []),
                "tools_payloads": meta.get("tools_and_payloads", []),
                "bypasses":      meta.get("bypass_techniques", []),
                "escalation":    meta.get("escalation_impact_tips", []),
            },
        )]


def manual_chapter(num: int, key: str, title: str) -> Type[BBBWorkflow]:
    cls = type(f"BBB_ch{num}", (ManualChapter,),
               {"key": key, "chapter_number": num, "title": title})
    register(cls)
    return cls
