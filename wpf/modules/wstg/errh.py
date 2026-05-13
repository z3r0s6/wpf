"""WSTG-ERRH — Error Handling (2 tests). Trigger common error paths and inspect."""
from __future__ import annotations

import httpx as _httpx

from ...core.finding import Finding
from ...core.roi import _STACK_TRACE_HINTS, _DEBUG_PAGE_HINTS
from ...core.scope import Scope
from ..checklists import wstg_by_category
from ._base import WstgTest, manual_class_for, register


@register
class WSTG_ERRH_01(WstgTest):
    id = "WSTG-ERRH-01"
    name = "Testing for Improper Error Handling"
    category = "ERRH"

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        base = (target if "://" in target else "https://" + target).rstrip("/")
        scope.check_url(base, action="wstg.errh-01")
        probe_paths = ("/nonexistent-" + "a" * 30, "/?id='", "/%00", "/a/b/c.dontexist.actual",
                       "/admin/../etc/passwd", "/__debug__")
        findings: list[Finding] = []
        async with _httpx.AsyncClient(timeout=15, http2=True,
                                      headers={"User-Agent": scope.user_agent}, verify=False) as c:
            for p in probe_paths:
                try:
                    r = await c.get(base + p)
                except Exception:
                    continue
                body = r.text or ""
                for hint in (*_STACK_TRACE_HINTS, *_DEBUG_PAGE_HINTS):
                    if hint in body:
                        findings.append(Finding(
                            code="ERRH-VERBOSE",
                            title=f"Verbose error page on {p}",
                            severity="medium",
                            confidence="high",
                            asset=base + p,
                            description=f"Probe hit produced a debug/stack-trace response containing {hint!r}.",
                            recommendation="Disable framework debug mode in production and serve a generic error page.",
                            wstg_id=self.id, cwe="CWE-209",
                            evidence={"hint": hint, "excerpt": body[:1500]},
                        ))
                        break
        return findings


for _t in wstg_by_category("ERRH"):
    if _t["id"] != "WSTG-ERRH-01":
        manual_class_for(_t["id"], _t.get("name", _t["id"]), "ERRH", severity="info")
