"""WSTG test base class + manual-review fallback.

Every WSTG-XXX-NN test is a subclass of :class:`WstgTest`. Tests with a real
automated implementation override ``run()``. Tests that genuinely require human
judgement (business logic, file upload semantics, race conditions in the wild)
inherit :class:`ManualChecklistTest`, which emits a Finding stub the operator
fills in via ``wpf finding update``.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Type

from ...core.finding import Finding
from ...core.scope import Scope
from ..checklists import wstg_test

REGISTRY: dict[str, Type["WstgTest"]] = {}


def register(cls: Type["WstgTest"]) -> Type["WstgTest"]:
    REGISTRY[cls.id] = cls
    return cls


class WstgTest(ABC):
    id: str = ""
    name: str = ""
    category: str = ""
    aggressive: bool = False
    requires_tools: tuple[str, ...] = ()

    @classmethod
    def meta(cls) -> dict:
        return wstg_test(cls.id) or {}

    @abstractmethod
    async def run(self, target: str, *, scope: Scope, **kwargs) -> list[Finding]:
        ...


class ManualChecklistTest(WstgTest):
    """Emit a stub finding with the test metadata for human follow-up.

    Useful for tests where automation would produce noise rather than signal —
    e.g. business-logic flaws, file-upload abuse semantics, race conditions.
    """

    severity = "info"
    confidence = "low"

    async def run(self, target: str, *, scope: Scope, **kwargs) -> list[Finding]:
        scope.check_host(_strip_scheme(target), action=f"wstg.{self.id}")
        meta = self.meta()
        return [Finding(
            code=self.id,
            title=meta.get("name", self.name or self.id),
            severity=self.severity,
            confidence=self.confidence,
            asset=target,
            description=("Manual checklist test — automation would not add signal. "
                         + (meta.get("objective", "") or "")),
            recommendation="Follow the WSTG 'How to Test' steps and update the finding with evidence.",
            wstg_id=self.id,
            references=[
                f"https://owasp.org/www-project-web-security-testing-guide/v42/"
                + _wstg_url_for(self.id)
            ],
            evidence={
                "checklist": meta.get("how_to_test", []),
                "tools": meta.get("tools", []),
                "pages": meta.get("pages", ""),
            },
        )]


def _strip_scheme(target: str) -> str:
    from urllib.parse import urlparse
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split("/")[0].split(":")[0]


def _wstg_url_for(test_id: str) -> str:
    """Best-effort URL fragment for a WSTG test ID (returns empty string on miss)."""
    meta = wstg_test(test_id) or {}
    name = meta.get("name", "")
    cat  = meta.get("category", "")
    # WSTG URLs follow a pattern like:
    # 4-Web_Application_Security_Testing/07-Input_Validation_Testing/05-Testing_for_SQL_Injection
    return f"4-Web_Application_Security_Testing/  # {cat} {test_id} — {name}"


# Helper used by category modules to emit class definitions for every test in a category.

def manual_class_for(test_id: str, name: str, category: str,
                     severity: str = "info") -> Type[WstgTest]:
    """Dynamically build a ManualChecklistTest subclass for a given WSTG test."""
    cls_name = "WSTG_" + test_id.replace("-", "_")
    cls = type(cls_name, (ManualChecklistTest,),
               {"id": test_id, "name": name, "category": category, "severity": severity})
    register(cls)
    return cls
