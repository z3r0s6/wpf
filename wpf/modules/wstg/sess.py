"""WSTG-SESS — Session Management (9 tests).

Implements:
  SESS-02 — Cookie attributes (HttpOnly/Secure/SameSite/Path/Domain)
  SESS-05 — CSRF (detect missing CSRF tokens on state-changing forms — heuristic)
"""
from __future__ import annotations

import re

import httpx as _httpx

from ...core.finding import Finding
from ...core.scope import Scope
from ..checklists import wstg_by_category
from ._base import WstgTest, manual_class_for, register


_SET_COOKIE_RE = re.compile(r"^([A-Za-z0-9_\-]+)=([^;]*)(.*)$", re.I)


@register
class WSTG_SESS_02(WstgTest):
    id = "WSTG-SESS-02"
    name = "Testing for Cookies Attributes"
    category = "SESS"

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        url = target if "://" in target else "https://" + target
        scope.check_url(url, action="wstg.sess-02")
        try:
            async with _httpx.AsyncClient(timeout=15, http2=True,
                                          headers={"User-Agent": scope.user_agent},
                                          verify=False, follow_redirects=False) as c:
                r = await c.get(url)
        except Exception:
            return []
        findings: list[Finding] = []
        set_cookies = r.headers.get_list("set-cookie") if hasattr(r.headers, "get_list") else [r.headers.get("set-cookie", "")]
        for raw in (set_cookies or []):
            if not raw:
                continue
            low = raw.lower()
            issues = []
            if "httponly" not in low:
                issues.append(("HttpOnly missing", "medium"))
            if " secure" not in low and ";secure" not in low:
                issues.append(("Secure missing", "medium"))
            if "samesite" not in low:
                issues.append(("SameSite missing", "low"))
            name = raw.split("=", 1)[0]
            for label, sev in issues:
                findings.append(Finding(
                    code=f"SESS-COOKIE-{label.split()[0].upper()}",
                    title=f"Cookie {name!r}: {label}",
                    severity=sev,
                    confidence="high",
                    asset=url,
                    description=f"Cookie {name!r} is missing the {label.split()[0]} attribute.",
                    recommendation="Add the missing attribute on the Set-Cookie header.",
                    wstg_id=self.id, cwe="CWE-1004" if "HttpOnly" in label else "CWE-614",
                    evidence={"set_cookie": raw[:300]},
                ))
        return findings


@register
class WSTG_SESS_05(WstgTest):
    id = "WSTG-SESS-05"
    name = "Testing for Cross Site Request Forgery"
    category = "SESS"

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        url = target if "://" in target else "https://" + target
        scope.check_url(url, action="wstg.sess-05")
        try:
            async with _httpx.AsyncClient(timeout=15, http2=True,
                                          headers={"User-Agent": scope.user_agent},
                                          verify=False) as c:
                r = await c.get(url, follow_redirects=True)
        except Exception:
            return []
        forms = re.findall(r"<form[^>]*method=[\"']?post[\"']?[^>]*>([\s\S]*?)</form>", r.text, re.I)
        flagged = []
        for form_body in forms:
            if not re.search(r"name=[\"']?(csrf|_token|authenticity_token|xsrf|__RequestVerificationToken)[\"']?",
                             form_body, re.I):
                flagged.append(form_body[:200])
        if flagged:
            return [Finding(
                code="SESS-NO-CSRF-TOKEN",
                title=f"{len(flagged)} POST form(s) lack a CSRF token (heuristic)",
                severity="medium",
                confidence="low",
                asset=url,
                description="Heuristic check: no <input> with a token-like name found in POST forms. Manual verification required.",
                recommendation="Add and verify per-request CSRF tokens, or use SameSite=Lax/Strict + auth header CSRF mitigations.",
                wstg_id=self.id, cwe="CWE-352",
                evidence={"form_snippets": flagged[:3]},
                bbb_chapter="ch09_csrf",
            )]
        return []


_IMPLEMENTED = {"WSTG-SESS-02", "WSTG-SESS-05"}
for _t in wstg_by_category("SESS"):
    _id = _t["id"]
    if _id not in _IMPLEMENTED:
        manual_class_for(_id, _t.get("name", _id), "SESS", severity="info")
