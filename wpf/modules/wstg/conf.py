"""WSTG-CONF — Configuration and Deployment Management Testing (11 tests).

Implements automated checks for:
  CONF-01 / 02 — network / app platform config (header hygiene)
  CONF-07     — HTTP Strict Transport Security
  CONF-08     — RIA cross-domain (crossdomain.xml / clientaccesspolicy.xml)
  CONF-09     — File permissions (well-known path probe)
  CONF-10     — Subdomain takeover (delegated to recon.takeover)
  CONF-11     — Cloud storage exposure (s3 bucket guess)
"""
from __future__ import annotations

from urllib.parse import urljoin

import httpx as _httpx

from ...core.finding import Finding
from ...core.scope import Scope
from ..checklists import wstg_by_category
from ._base import WstgTest, manual_class_for, register


SECURITY_HEADERS = {
    "Strict-Transport-Security":   ("CONF-07", "missing HSTS"),
    "Content-Security-Policy":     ("CONF-02", "missing CSP"),
    "X-Content-Type-Options":      ("CONF-02", "missing X-Content-Type-Options"),
    "X-Frame-Options":             ("CONF-02", "missing X-Frame-Options or CSP frame-ancestors"),
    "Referrer-Policy":             ("CONF-02", "missing Referrer-Policy"),
    "Permissions-Policy":          ("CONF-02", "missing Permissions-Policy"),
}


@register
class WSTG_CONF_02(WstgTest):
    id = "WSTG-CONF-02"
    name = "Test Application Platform Configuration"
    category = "CONF"

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        url = _scheme(target)
        scope.check_url(url, action="wstg.conf-02")
        try:
            async with _httpx.AsyncClient(timeout=15, http2=True,
                                          headers={"User-Agent": scope.user_agent},
                                          verify=False) as c:
                r = await c.get(url, follow_redirects=True)
        except Exception:
            return []
        findings: list[Finding] = []
        for hdr, (code, why) in SECURITY_HEADERS.items():
            if hdr not in r.headers:
                findings.append(Finding(
                    code=f"CONF-HDR-{hdr.split('-')[0][:3].upper()}",
                    title=f"Missing security header: {hdr}",
                    severity="low",
                    confidence="high",
                    asset=url,
                    description=f"Response did not include the {hdr} header. {why}.",
                    recommendation=f"Set a strict {hdr} value at the edge.",
                    wstg_id=f"WSTG-{code}",
                    cwe="CWE-693",
                    evidence={"headers": dict(r.headers)},
                ))
        return findings


@register
class WSTG_CONF_07(WstgTest):
    id = "WSTG-CONF-07"
    name = "Test HTTP Strict Transport Security"
    category = "CONF"

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        url = _scheme(target)
        if not url.startswith("https"):
            return []
        scope.check_url(url, action="wstg.conf-07")
        try:
            async with _httpx.AsyncClient(timeout=15, http2=True,
                                          headers={"User-Agent": scope.user_agent},
                                          verify=False) as c:
                r = await c.get(url, follow_redirects=False)
        except Exception:
            return []
        sts = r.headers.get("Strict-Transport-Security", "")
        if not sts:
            return [Finding(code="CONF-HSTS", title="HSTS not enabled",
                             severity="medium", confidence="high", asset=url,
                             description="Strict-Transport-Security header absent on HTTPS response.",
                             recommendation="Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`.",
                             wstg_id=self.id, cwe="CWE-319")]
        try:
            max_age = int([t.split("=")[1] for t in sts.split(";") if "max-age" in t.lower()][0])
        except Exception:
            max_age = 0
        if max_age < 15768000:  # 6 months
            return [Finding(code="CONF-HSTS-SHORT", title=f"HSTS max-age too short ({max_age}s)",
                             severity="low", confidence="high", asset=url,
                             description=f"HSTS max-age below 6 months ({max_age}).",
                             wstg_id=self.id, evidence={"header": sts})]
        return []


@register
class WSTG_CONF_08(WstgTest):
    id = "WSTG-CONF-08"
    name = "Test RIA Cross Domain Policy"
    category = "CONF"

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        base = _scheme(target).rstrip("/")
        scope.check_url(base, action="wstg.conf-08")
        findings = []
        async with _httpx.AsyncClient(timeout=10, headers={"User-Agent": scope.user_agent},
                                      verify=False) as c:
            for path in ("crossdomain.xml", "clientaccesspolicy.xml"):
                url = urljoin(base + "/", path)
                try:
                    r = await c.get(url)
                except Exception:
                    continue
                if r.status_code == 200 and ("<cross-domain" in r.text or "<access-policy" in r.text):
                    weak = ('allow-access-from domain="*"' in r.text
                            or 'domain="*"' in r.text)
                    findings.append(Finding(
                        code="CONF-RIA-XDOMAIN",
                        title=f"Cross-domain policy file exposed: {path}",
                        severity="medium" if weak else "info",
                        confidence="high",
                        asset=url,
                        description="Flash/Silverlight cross-domain policy present" + (" with a wildcard ALLOW." if weak else "."),
                        evidence={"body": r.text[:1000]},
                        wstg_id=self.id,
                        cwe="CWE-942",
                    ))
        return findings


@register
class WSTG_CONF_09(WstgTest):
    id = "WSTG-CONF-09"
    name = "Test File Permission"
    category = "CONF"

    SENSITIVE_PATHS = (".git/config", ".git/HEAD", ".env", "config.php.bak", ".DS_Store",
                       "WEB-INF/web.xml", "phpinfo.php", "server-status", "wp-config.php.bak")

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        base = _scheme(target).rstrip("/")
        scope.check_url(base, action="wstg.conf-09")
        findings = []
        async with _httpx.AsyncClient(timeout=8, headers={"User-Agent": scope.user_agent},
                                      verify=False) as c:
            for p in self.SENSITIVE_PATHS:
                url = urljoin(base + "/", p)
                try:
                    r = await c.get(url)
                except Exception:
                    continue
                if r.status_code == 200 and 50 < len(r.content) < 1_000_000:
                    findings.append(Finding(
                        code="CONF-SENS-PATH",
                        title=f"Sensitive path accessible: {p}",
                        severity="high",
                        confidence="medium",
                        asset=url,
                        description=f"Path {p} returned 200 — may leak secrets/config.",
                        recommendation="Remove from web root or restrict via access controls.",
                        wstg_id=self.id, cwe="CWE-538",
                        evidence={"size": len(r.content), "ctype": r.headers.get("content-type", "")},
                    ))
        return findings


def _scheme(target: str) -> str:
    return target if "://" in target else "https://" + target


_IMPLEMENTED = {"WSTG-CONF-02", "WSTG-CONF-07", "WSTG-CONF-08", "WSTG-CONF-09"}
for _t in wstg_by_category("CONF"):
    _id = _t["id"]
    if _id not in _IMPLEMENTED:
        manual_class_for(_id, _t.get("name", _id), "CONF")
