"""Chapter 8 — Clickjacking. Delegates to WSTG-CLNT-09."""
from __future__ import annotations

from ...core.finding import Finding
from ...core.scope import Scope
from ..wstg.clnt import WSTG_CLNT_09
from ._shared import BBBWorkflow, register


@register
class BBB_ch08(BBBWorkflow):
    key = "ch08_clickjacking"
    chapter_number = 8
    title = "Clickjacking"

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        findings = await WSTG_CLNT_09().run(target, scope=scope)
        for f in findings:
            f.bbb_chapter = self.key
        return findings
