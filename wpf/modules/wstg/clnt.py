"""WSTG-CLNT — Client-side Testing (13 tests).

Implements CLNT-07 (clickjacking via X-Frame-Options / CSP frame-ancestors check)
and CLNT-12 (CORS misconfiguration probe). The remaining tests are manual-checklist
stubs (DOM XSS, JavaScript execution, clipboard, Web Messaging, Web Storage, etc.).
"""
from __future__ import annotations

import httpx as _httpx

from ...core.finding import Finding
from ...core.scope import Scope
from ..checklists import wstg_by_category
from ._base import WstgTest, manual_class_for, register


@register
class WSTG_CLNT_09(WstgTest):
    id = "WSTG-CLNT-09"
    name = "Testing for Clickjacking"
    category = "CLNT"

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        url = target if "://" in target else "https://" + target
        scope.check_url(url, action="wstg.clnt-09")
        try:
            async with _httpx.AsyncClient(timeout=15, http2=True,
                                          headers={"User-Agent": scope.user_agent},
                                          verify=False) as c:
                r = await c.get(url, follow_redirects=False)
        except Exception:
            return []
        xfo = r.headers.get("X-Frame-Options", "").lower()
        csp = r.headers.get("Content-Security-Policy", "").lower()
        has_ancestor = "frame-ancestors" in csp
        if not xfo and not has_ancestor:
            return [Finding(
                code="CLNT-CLICKJACK",
                title="No clickjacking protection (X-Frame-Options / CSP frame-ancestors)",
                severity="medium",
                confidence="high",
                asset=url,
                description="Response lacks both X-Frame-Options and a CSP frame-ancestors directive.",
                recommendation="Set 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors 'self'.",
                wstg_id=self.id, cwe="CWE-1021",
            )]
        return []


@register
class WSTG_CLNT_07(WstgTest):
    id = "WSTG-CLNT-07"
    name = "Testing Cross Origin Resource Sharing"
    category = "CLNT"

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        url = target if "://" in target else "https://" + target
        scope.check_url(url, action="wstg.clnt-07")
        evil = "https://attacker.example"
        try:
            async with _httpx.AsyncClient(timeout=15, http2=True,
                                          headers={"User-Agent": scope.user_agent, "Origin": evil},
                                          verify=False) as c:
                r = await c.get(url, follow_redirects=False)
        except Exception:
            return []
        aco = r.headers.get("Access-Control-Allow-Origin", "")
        acc = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        if aco == evil and acc == "true":
            return [Finding(
                code="CLNT-CORS-REFL",
                title="CORS reflects arbitrary Origin with credentials=true",
                severity="high",
                confidence="high",
                asset=url,
                description=f"Server returned ACAO: {evil} and ACAC: true when probed with Origin: {evil}.",
                recommendation="Whitelist origins explicitly; never combine reflected Origin with credentials.",
                wstg_id=self.id, cwe="CWE-942",
                evidence={"acao": aco, "acac": acc, "origin_sent": evil},
            )]
        if aco == "*" and acc == "true":
            return [Finding(
                code="CLNT-CORS-WILD",
                title="ACAO * + ACAC: true (browsers refuse this — likely buggy config)",
                severity="low",
                confidence="high",
                asset=url,
                description="Wildcard origin with credentials is invalid per the CORS spec.",
                wstg_id=self.id, cwe="CWE-942",
            )]
        return []


_IMPLEMENTED = {"WSTG-CLNT-09", "WSTG-CLNT-07"}
for _t in wstg_by_category("CLNT"):
    _id = _t["id"]
    if _id not in _IMPLEMENTED:
        manual_class_for(_id, _t.get("name", _id), "CLNT", severity="info")
