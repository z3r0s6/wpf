"""Chapter 16 — Server-Side Template Injection. Delegates to WSTG-INPV-18."""
from __future__ import annotations

from ...core.finding import Finding
from ...core.scope import Scope
from ..wstg.inpv import WSTG_INPV_18
from ._shared import BBBWorkflow, register


@register
class BBB_ch16(BBBWorkflow):
    key = "ch16_ssti"
    chapter_number = 16
    title = "Server-Side Template Injection"

    async def run(self, target: str, *, scope: Scope, urls: list[str] | None = None, **kw) -> list[Finding]:
        findings = await WSTG_INPV_18().run(target, scope=scope, urls=urls)
        for f in findings:
            f.bbb_chapter = self.key
        return findings
