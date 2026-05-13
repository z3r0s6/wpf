"""Chapter 10 — Insecure Direct Object References.

IDOR requires session/auth context — automated detection is heuristic at best.
This runner enumerates numeric/UUID-shaped path/query params, optionally
fetches them with two cookie sets (--cookieA / --cookieB) and flags when both
responses contain similar private-data structures.
"""
from __future__ import annotations

import re
from typing import Iterable

import httpx as _httpx

from ...core.finding import Finding
from ...core.scope import Scope
from ._shared import BBBWorkflow, register


_NUMERIC_PATH = re.compile(r"/(\d{2,})(?=/|$|\?)")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.I)


def _candidates(urls: Iterable[str]) -> list[str]:
    out = set()
    for u in urls:
        if _NUMERIC_PATH.search(u) or _UUID.search(u):
            out.add(u)
    return sorted(out)


@register
class BBB_ch10(BBBWorkflow):
    key = "ch10_idor"
    chapter_number = 10
    title = "Insecure Direct Object References"

    async def run(self, target: str, *, scope: Scope, urls: list[str] | None = None,
                  cookieA: str = "", cookieB: str = "", **kw) -> list[Finding]:
        urls = urls or [target]
        cands = _candidates(urls)
        if not cands:
            return []
        if not (cookieA and cookieB):
            return [Finding(
                code="BBB-IDOR-CANDIDATES",
                title=f"{len(cands)} URLs look like IDOR candidates",
                severity="info", confidence="low",
                asset=cands[0],
                description="Numeric or UUID path params detected. Run with --cookieA / --cookieB to compare.",
                wstg_id="WSTG-ATHZ-04", cwe="CWE-639", bbb_chapter=self.key,
                evidence={"candidates": cands[:30]},
            )]
        findings: list[Finding] = []
        async with _httpx.AsyncClient(timeout=15, http2=True,
                                      headers={"User-Agent": scope.user_agent},
                                      verify=False) as c:
            for u in cands[:25]:
                scope.check_url(u, action="bbb.ch10")
                try:
                    rA = await c.get(u, headers={"Cookie": cookieA})
                    rB = await c.get(u, headers={"Cookie": cookieB})
                except Exception:
                    continue
                if rA.status_code == 200 and rB.status_code == 200 and rA.text and rA.text == rB.text:
                    findings.append(Finding(
                        code="BBB-IDOR-CONFIRMED",
                        title="Identical 200 OK across two sessions (probable IDOR)",
                        severity="high", confidence="medium",
                        asset=u,
                        description=("Same resource returned to both supplied sessions — access control "
                                     "may be missing. Manually verify the response holds private data."),
                        wstg_id="WSTG-ATHZ-04", cwe="CWE-639", bbb_chapter=self.key,
                        evidence={"snippet_len": len(rA.text)},
                    ))
        return findings
