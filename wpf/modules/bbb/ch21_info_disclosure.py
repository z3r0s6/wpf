"""Chapter 21 — Information Disclosure.

Reuses INFO-03 + INFO-05 + CONF-09 detectors and bundles findings under the
bbb chapter for reporting.
"""
from __future__ import annotations

from ...core.finding import Finding
from ...core.scope import Scope
from ..wstg.conf import WSTG_CONF_09
from ..wstg.info import WSTG_INFO_03, WSTG_INFO_05
from ._shared import BBBWorkflow, register


@register
class BBB_ch21(BBBWorkflow):
    key = "ch21_info_disclosure"
    chapter_number = 21
    title = "Information Disclosure"

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        all_findings: list[Finding] = []
        for runner in (WSTG_INFO_03(), WSTG_INFO_05(), WSTG_CONF_09()):
            try:
                all_findings.extend(await runner.run(target, scope=scope))
            except Exception:
                continue
        for f in all_findings:
            f.bbb_chapter = self.key
        return all_findings
