"""Chapter 6 — Cross-Site Scripting.

Vickie's methodology condensed:
  1. Find input opportunities — reflection points, params, fragments, paths.
  2. Inject canary, view source, escalate to polyglots and event handlers.
  3. Bypass filters (case, encoding, nested tags, JS/data URI).
  4. Escalate to CSRF token theft / cookie theft / phishing / admin-page chain.
"""
from __future__ import annotations

import httpx as _httpx

from ...core.finding import Finding
from ...core.scope import Scope
from ...tools import qsreplace
from ...tools import registry as toolreg
from ._shared import BBBWorkflow, register


CANARY = "wpfXSSv1</xx>"
POLYGLOT = "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"`/+/onmouseover=1/+/[*/[]/+alert(42)//'>"


@register
class BBB_ch06(BBBWorkflow):
    key = "ch06_xss"
    chapter_number = 6
    title = "Cross-Site Scripting"

    async def run(self, target: str, *, scope: Scope, urls: list[str] | None = None, **kw) -> list[Finding]:
        urls = urls or [target]
        findings: list[Finding] = []

        # Step 1: canary reflection
        async with _httpx.AsyncClient(timeout=15, http2=True,
                                      headers={"User-Agent": scope.user_agent}, verify=False) as c:
            for u in qsreplace.replace(urls, CANARY):
                scope.check_url(u, action="bbb.ch06.canary")
                try:
                    r = await c.get(u)
                except Exception:
                    continue
                if CANARY in r.text:
                    findings.append(Finding(
                        code="BBB-XSS-REFL",
                        title="Reflected XSS canary unencoded",
                        severity="high", confidence="medium",
                        asset=u,
                        description="The canary string was reflected into the HTML body verbatim.",
                        recommendation="Output-encode based on context (HTML body / attribute / script / URL).",
                        wstg_id="WSTG-INPV-01", cwe="CWE-79", bbb_chapter=self.key,
                        evidence={"canary": CANARY, "url": u},
                    ))

        # Step 2: optional dalfox confirmation
        dalfox = toolreg.get("dalfox")
        if dalfox and dalfox.available() and findings:
            for f in findings[:5]:
                try:
                    res = await dalfox.run(f.asset, scope=scope)
                    if res.parsed:
                        f.confidence = "confirmed"
                        f.evidence["dalfox_hits"] = res.parsed[:5]
                except Exception:
                    continue

        return findings
