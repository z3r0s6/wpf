"""Chapter 5 — Web Hacking Reconnaissance. Delegates to wpf.modules.recon.pipeline."""
from __future__ import annotations

from ...core.finding import Finding
from ...core.scope import Scope
from ..recon import pipeline
from ._shared import BBBWorkflow, register


@register
class BBB_ch05(BBBWorkflow):
    key = "ch05_recon"
    chapter_number = 5
    title = "Web Hacking Reconnaissance"

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        result = await pipeline.run(target, scope=scope, mode=kw.get("mode", "passive"))
        # findings are inserted by the pipeline itself; we re-load them by code/asset shortly.
        return [Finding(
            code="BBB-CH05",
            title=f"Recon complete: {len(result.subdomains)} subdomains, {len(result.url_facts)} live",
            severity="info", confidence="high", asset=target,
            description=f"BBB Ch.5 recon pipeline finished. Pause? {result.paused} ({result.pause_reason})",
            bbb_chapter=self.key,
            evidence=result.summary(),
        )]
