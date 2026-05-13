"""Chapter 20 — Subdomain Takeover. Delegates to recon.takeover."""
from __future__ import annotations

from ...core.finding import Finding
from ...core.scope import Scope
from ..recon import takeover
from ._shared import BBBWorkflow, register


@register
class BBB_ch20(BBBWorkflow):
    key = "ch20_subdomain_takeover"
    chapter_number = 20
    title = "Subdomain Takeover"

    async def run(self, target: str, *, scope: Scope, hosts: list[str] | None = None, **kw) -> list[Finding]:
        hosts = hosts or [target]
        findings = await takeover.check(hosts, scope=scope)
        for f in findings:
            f.bbb_chapter = self.key
        return findings
