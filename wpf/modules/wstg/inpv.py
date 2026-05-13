"""WSTG-INPV — Input Validation (19 tests).

Implements automated runners for INPV-01 (reflected XSS canary), INPV-05 (SQLi
via sqlmap; aggressive), INPV-07 (LDAP injection — manual), INPV-18 (SSTI via
small heuristic). All other tests are manual-checklist stubs that surface
WSTG methodology + tool hints (the BBB workflows under wpf.modules.bbb cover
deeper hunts for XSS/SQLi/SSTI/XXE/etc.).
"""
from __future__ import annotations

import re

import httpx as _httpx

from ...core.finding import Finding
from ...core.scope import Scope, ScopeError
from ...tools import qsreplace
from ..checklists import wstg_by_category
from ._base import WstgTest, manual_class_for, register


_XSS_CANARY = "wpf__c4N4RY__</xx>"  # easy to grep
_SQLI_CANARY = "'\"`)("            # cheap error-based probe
_SSTI_CANARY = "${7*7}{{7*7}}"     # 49 / 49 if rendered


@register
class WSTG_INPV_01(WstgTest):
    id = "WSTG-INPV-01"
    name = "Testing for Reflected Cross Site Scripting"
    category = "INPV"

    async def run(self, target: str, *, scope: Scope, urls: list[str] | None = None, **kw) -> list[Finding]:
        urls = urls or [target]
        findings: list[Finding] = []
        async with _httpx.AsyncClient(timeout=15, http2=True,
                                      headers={"User-Agent": scope.user_agent}, verify=False) as c:
            for u in qsreplace.replace(urls, _XSS_CANARY):
                scope.check_url(u, action="wstg.inpv-01")
                try:
                    r = await c.get(u)
                except Exception:
                    continue
                if _XSS_CANARY in r.text:
                    findings.append(Finding(
                        code="INPV-XSS-REFL",
                        title="Unencoded parameter reflection (possible XSS)",
                        severity="high",
                        confidence="medium",
                        asset=u,
                        description="Canary string was reflected unencoded in the response.",
                        recommendation="Output-encode by context (HTML / attribute / JS / URL).",
                        wstg_id=self.id, cwe="CWE-79", bbb_chapter="ch06_xss",
                        evidence={"canary": _XSS_CANARY, "url": u},
                    ))
        return findings


@register
class WSTG_INPV_05(WstgTest):
    """Reflective probe for SQLi-shaped error messages; aggressive sqlmap path optional."""
    id = "WSTG-INPV-05"
    name = "Testing for SQL Injection"
    category = "INPV"
    aggressive = True
    SQL_ERROR_RE = re.compile(
        r"(SQL syntax|mysql_fetch|ORA-\d{4,5}|PostgreSQL.*ERROR|sqlite3\.OperationalError"
        r"|System\.Data\.SqlClient|ODBC SQL Server Driver|Warning: mysqli)",
        re.I,
    )

    async def run(self, target: str, *, scope: Scope, urls: list[str] | None = None, **kw) -> list[Finding]:
        urls = urls or [target]
        findings: list[Finding] = []
        # 1) Cheap reflective probe — observable error messages
        async with _httpx.AsyncClient(timeout=15, http2=True,
                                      headers={"User-Agent": scope.user_agent}, verify=False) as c:
            for u in qsreplace.replace(urls, _SQLI_CANARY):
                scope.check_url(u, action="wstg.inpv-05.probe")
                try:
                    r = await c.get(u)
                except Exception:
                    continue
                if self.SQL_ERROR_RE.search(r.text or ""):
                    findings.append(Finding(
                        code="INPV-SQLI-ERR",
                        title="SQL error disclosure on canary input",
                        severity="high",
                        confidence="medium",
                        asset=u,
                        description="A characteristic SQL error message was returned for malformed input — likely SQL injection.",
                        recommendation="Use parameterised queries / ORM bindings. Validate and least-privilege the DB user.",
                        wstg_id=self.id, cwe="CWE-89", bbb_chapter="ch11_sqli",
                        evidence={"snippet": _grep(self.SQL_ERROR_RE, r.text)},
                    ))
        # 2) Aggressive sqlmap — only with explicit scope.aggressive
        if scope.aggressive and findings:
            from ...tools import registry as toolreg
            sqlmap = toolreg.get("sqlmap")
            if sqlmap and sqlmap.available():
                for f in findings[:3]:
                    try:
                        res = await sqlmap.run(f.asset, scope=scope, level=2, risk=1)
                        if "is vulnerable" in (res.raw.stdout or "").lower():
                            f.confidence = "confirmed"
                            f.evidence["sqlmap_excerpt"] = res.raw.stdout[-1500:]
                    except ScopeError:
                        pass
        return findings


@register
class WSTG_INPV_18(WstgTest):
    id = "WSTG-INPV-18"
    name = "Testing for Server-Side Template Injection"
    category = "INPV"

    async def run(self, target: str, *, scope: Scope, urls: list[str] | None = None, **kw) -> list[Finding]:
        urls = urls or [target]
        findings: list[Finding] = []
        async with _httpx.AsyncClient(timeout=15, http2=True,
                                      headers={"User-Agent": scope.user_agent}, verify=False) as c:
            for u in qsreplace.replace(urls, _SSTI_CANARY):
                scope.check_url(u, action="wstg.inpv-18")
                try:
                    r = await c.get(u)
                except Exception:
                    continue
                if "49" in (r.text or "") and _SSTI_CANARY not in (r.text or ""):
                    findings.append(Finding(
                        code="INPV-SSTI",
                        title="Possible Server-Side Template Injection",
                        severity="critical",
                        confidence="low",
                        asset=u,
                        description="Template expression ${7*7}/{{7*7}} appears to have been evaluated.",
                        recommendation="Disable template evaluation on untrusted input; use safe rendering primitives.",
                        wstg_id=self.id, cwe="CWE-1336", bbb_chapter="ch16_ssti",
                        evidence={"canary": _SSTI_CANARY, "url": u},
                    ))
        return findings


def _grep(pat: re.Pattern, text: str) -> str:
    m = pat.search(text or "")
    return m.group(0) if m else ""


_IMPLEMENTED = {"WSTG-INPV-01", "WSTG-INPV-05", "WSTG-INPV-18"}
for _t in wstg_by_category("INPV"):
    _id = _t["id"]
    if _id not in _IMPLEMENTED:
        manual_class_for(_id, _t.get("name", _id), "INPV", severity="info")
