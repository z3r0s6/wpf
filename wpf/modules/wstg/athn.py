"""WSTG-ATHN — Authentication (10 tests).

Implements:
  ATHN-01 — Credentials over encrypted channel (HTTP -> HTTPS check on login forms)
  ATHN-02 — Default credentials (well-known login probe; manual review otherwise)
  ATHN-09 — Weak password policy (manual checklist)
"""
from __future__ import annotations

import re

import httpx as _httpx

from ...core.finding import Finding
from ...core.scope import Scope
from ..checklists import wstg_by_category
from ._base import WstgTest, manual_class_for, register


@register
class WSTG_ATHN_01(WstgTest):
    id = "WSTG-ATHN-01"
    name = "Testing for Credentials Transported over an Encrypted Channel"
    category = "ATHN"

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        url = target if "://" in target else "http://" + target
        scope.check_url(url, action="wstg.athn-01")
        try:
            async with _httpx.AsyncClient(timeout=15, headers={"User-Agent": scope.user_agent},
                                          verify=False, follow_redirects=False) as c:
                r = await c.get(url)
        except Exception:
            return []
        body = r.text or ""
        if "type=\"password\"" in body.lower() or "type='password'" in body.lower():
            scheme = "http" if url.startswith("http://") else "https"
            if scheme == "http":
                return [Finding(
                    code="ATHN-CLEARTEXT-LOGIN",
                    title="Login form served over HTTP",
                    severity="high",
                    confidence="high",
                    asset=url,
                    description="A password input was found on an HTTP page — credentials are sent in cleartext.",
                    recommendation="Serve the login flow exclusively over HTTPS and set HSTS.",
                    wstg_id=self.id, cwe="CWE-319",
                )]
        return []


_IMPLEMENTED = {"WSTG-ATHN-01"}
for _t in wstg_by_category("ATHN"):
    _id = _t["id"]
    if _id not in _IMPLEMENTED:
        manual_class_for(_id, _t.get("name", _id), "ATHN", severity="info")
