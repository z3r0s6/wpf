"""Chapter 9 — Cross-Site Request Forgery. Delegates to WSTG-SESS-05."""
from __future__ import annotations

from ...core.finding import Finding
from ...core.scope import Scope
from ..wstg.sess import WSTG_SESS_05
from ._shared import BBBWorkflow, register


@register
class BBB_ch09(BBBWorkflow):
    key = "ch09_csrf"
    chapter_number = 9
    title = "Cross-Site Request Forgery"

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        findings = await WSTG_SESS_05().run(target, scope=scope)
        for f in findings:
            f.bbb_chapter = self.key
        return findings
