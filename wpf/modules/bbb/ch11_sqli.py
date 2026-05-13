"""Chapter 11 — SQL Injection. Delegates to WSTG-INPV-05."""
from __future__ import annotations

from ...core.finding import Finding
from ...core.scope import Scope
from ..wstg.inpv import WSTG_INPV_05
from ._shared import BBBWorkflow, register


@register
class BBB_ch11(BBBWorkflow):
    key = "ch11_sqli"
    chapter_number = 11
    title = "SQL Injection"

    async def run(self, target: str, *, scope: Scope, urls: list[str] | None = None, **kw) -> list[Finding]:
        findings = await WSTG_INPV_05().run(target, scope=scope, urls=urls)
        for f in findings:
            f.bbb_chapter = self.key
        return findings
