"""WSTG-INFO — Information Gathering (10 tests).

Implements automated checks for INFO-02, INFO-03, INFO-05, INFO-08 (tech fingerprint).
The remaining INFO tests are manual-checklist stubs that surface the WSTG
methodology + tool hints.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import urljoin

import httpx as _httpx

from ...core.finding import Finding
from ...core.scope import Scope
from ..checklists import wstg_by_category
from ._base import ManualChecklistTest, WstgTest, manual_class_for, register


# -------- WSTG-INFO-02: Fingerprint Web Server (banner grab + tech) --------------

@register
class WSTG_INFO_02(WstgTest):
    id = "WSTG-INFO-02"
    name = "Fingerprint Web Server"
    category = "INFO"

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        url = _ensure_scheme(target)
        scope.check_url(url, action="wstg.info-02")
        async with _httpx.AsyncClient(http2=True, timeout=20, headers={"User-Agent": scope.user_agent},
                                      verify=False) as c:
            try:
                r = await c.get(url, follow_redirects=False)
            except Exception as e:
                return []
            server = r.headers.get("Server", "")
            powered = r.headers.get("X-Powered-By", "")
            tech = r.headers.get("X-AspNet-Version") or r.headers.get("X-Generator")
        title = f"Web server fingerprint for {url}"
        body = ", ".join(filter(None, [server, powered, tech])) or "(no Server/X-Powered-By header)"
        return [Finding(
            code="INFO-WS-FP",
            title=title,
            severity="info",
            confidence="high",
            asset=url,
            description=f"Banner: {body}",
            evidence={"server": server, "x_powered_by": powered, "extra": tech},
            recommendation="Suppress version info via reverse-proxy directives if not needed.",
            wstg_id=self.id,
            references=["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/01-Information_Gathering/02-Fingerprint_Web_Server"],
        )]


# -------- WSTG-INFO-03: Review webserver metafiles (robots/sitemap/security.txt) -----

@register
class WSTG_INFO_03(WstgTest):
    id = "WSTG-INFO-03"
    name = "Review Webserver Metafiles for Information Leakage"
    category = "INFO"

    metafiles = ("robots.txt", "sitemap.xml", "security.txt", ".well-known/security.txt", "humans.txt")

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        base = _ensure_scheme(target)
        scope.check_url(base, action="wstg.info-03")
        findings: list[Finding] = []
        async with _httpx.AsyncClient(timeout=15, headers={"User-Agent": scope.user_agent},
                                      verify=False) as c:
            for path in self.metafiles:
                url = urljoin(base + "/", path)
                try:
                    r = await c.get(url)
                except Exception:
                    continue
                if r.status_code == 200 and r.text.strip():
                    findings.append(Finding(
                        code="INFO-METAFILE",
                        title=f"Metafile present: {path}",
                        severity="info",
                        confidence="high",
                        asset=url,
                        description=f"{path} returned 200 with {len(r.text)} bytes — review for sensitive paths.",
                        evidence={"snippet": r.text[:1000]},
                        wstg_id=self.id,
                    ))
        return findings


# -------- WSTG-INFO-05: Review webpage content for info leakage ----------------

@register
class WSTG_INFO_05(WstgTest):
    id = "WSTG-INFO-05"
    name = "Review Webpage Content for Information Leakage"
    category = "INFO"
    COMMENT_RE = re.compile(r"<!--([\s\S]*?)-->")
    INTERESTING = re.compile(r"(todo|fixme|hack|debug|password|api[_-]?key|secret|aws|internal|admin)", re.I)

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        url = _ensure_scheme(target)
        scope.check_url(url, action="wstg.info-05")
        async with _httpx.AsyncClient(timeout=20, headers={"User-Agent": scope.user_agent},
                                      verify=False) as c:
            try:
                r = await c.get(url, follow_redirects=True)
            except Exception:
                return []
        findings: list[Finding] = []
        for m in self.COMMENT_RE.finditer(r.text):
            txt = m.group(1).strip()
            if self.INTERESTING.search(txt) and len(txt) < 500:
                findings.append(Finding(
                    code="INFO-COMMENT-LEAK",
                    title="Interesting HTML comment",
                    severity="low",
                    confidence="low",
                    asset=url,
                    description=f"HTML comment matched sensitive-word pattern.",
                    evidence={"comment": txt[:300]},
                    wstg_id=self.id,
                ))
        return findings


# -------- WSTG-INFO-08: Fingerprint Web Application Framework -----------------

@register
class WSTG_INFO_08(WstgTest):
    id = "WSTG-INFO-08"
    name = "Fingerprint Web Application Framework"
    category = "INFO"

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        url = _ensure_scheme(target)
        scope.check_url(url, action="wstg.info-08")
        from ...tools import registry as toolreg
        whatweb = toolreg.get("whatweb")
        if whatweb and whatweb.available():
            try:
                res = await whatweb.run(url, scope=scope)
                techs = res.parsed or []
                return [Finding(
                    code="INFO-FRAMEWORK-FP",
                    title="Application framework fingerprint",
                    severity="info",
                    confidence="medium",
                    asset=url,
                    description="whatweb identified the following technologies.",
                    evidence={"whatweb": techs[:5]},
                    wstg_id=self.id,
                )]
            except Exception:
                pass
        # Fallback: parse headers + meta-generator
        try:
            async with _httpx.AsyncClient(timeout=15, headers={"User-Agent": scope.user_agent},
                                          verify=False) as c:
                r = await c.get(url, follow_redirects=True)
            tech = {
                "Server": r.headers.get("Server"),
                "X-Powered-By": r.headers.get("X-Powered-By"),
                "X-Generator": r.headers.get("X-Generator"),
                "X-AspNet-Version": r.headers.get("X-AspNet-Version"),
            }
            gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', r.text, re.I)
            if gen:
                tech["meta-generator"] = gen.group(1)
        except Exception:
            return []
        return [Finding(code="INFO-FRAMEWORK-FP", title="Framework fingerprint (header-based)",
                        severity="info", confidence="low", asset=url, description="Header-based detection.",
                        evidence={k: v for k, v in tech.items() if v}, wstg_id=self.id)]


def _ensure_scheme(target: str) -> str:
    if "://" not in target:
        return "https://" + target
    return target


# Auto-register every remaining INFO test as a manual-checklist stub.
_IMPLEMENTED = {"WSTG-INFO-02", "WSTG-INFO-03", "WSTG-INFO-05", "WSTG-INFO-08"}
for _t in wstg_by_category("INFO"):
    _id = _t["id"]
    if _id not in _IMPLEMENTED:
        manual_class_for(_id, _t.get("name", _id), "INFO")
