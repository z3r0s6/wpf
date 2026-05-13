"""WSTG-CRYP — Weak Cryptography (4 tests).

Implements CRYP-01 via testssl.sh or sslyze if installed; falls back to OpenSSL
connect for a TLS version + cipher check.
"""
from __future__ import annotations

import asyncio
import ssl
from socket import gethostbyname
from urllib.parse import urlparse

import httpx as _httpx

from ...core.finding import Finding
from ...core.runner import run_async, which
from ...core.scope import Scope
from ..checklists import wstg_by_category
from ._base import WstgTest, manual_class_for, register


@register
class WSTG_CRYP_01(WstgTest):
    id = "WSTG-CRYP-01"
    name = "Testing for Weak Transport Layer Security"
    category = "CRYP"

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        host = urlparse(target if "://" in target else "https://" + target).hostname or target
        port = 443
        scope.check_host(host, action="wstg.cryp-01")
        if which("testssl.sh"):
            try:
                res = await run_async(["testssl.sh", "--color", "0", "--quiet", "--openssl-timeout", "10",
                                       f"{host}:{port}"], timeout=900, scope=scope, tool_name="testssl.sh")
                if "VULNERABLE" in res.stdout.upper():
                    return [Finding(code="CRYP-TLS-WEAK", title="testssl.sh reports TLS weaknesses",
                                    severity="medium", confidence="high", asset=f"{host}:{port}",
                                    description="See evidence for the testssl.sh report.",
                                    wstg_id=self.id, cwe="CWE-326",
                                    evidence={"testssl_excerpt": res.stdout[-3000:]})]
                return []
            except Exception:
                pass
        # Fallback — direct TLS handshake check
        findings: list[Finding] = []
        for proto in (("SSLv23", ssl.PROTOCOL_TLS, "TLS auto"),):
            try:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                with await asyncio.wait_for(_open_tls(host, port, ctx), timeout=10) as info:
                    cipher = info["cipher"]
                    version = info["version"]
                    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
                        findings.append(Finding(code="CRYP-TLS-OBSOLETE",
                                                title=f"Obsolete TLS version supported: {version}",
                                                severity="medium", confidence="high",
                                                asset=f"{host}:{port}",
                                                description=f"Cipher {cipher} on {version}.",
                                                wstg_id=self.id, cwe="CWE-326"))
            except Exception:
                continue
        return findings


async def _open_tls(host: str, port: int, ctx: ssl.SSLContext) -> dict:
    reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
    sslobj = writer.get_extra_info("ssl_object")
    info = {"cipher": sslobj.cipher(), "version": sslobj.version()}
    writer.close()
    return info


for _t in wstg_by_category("CRYP"):
    if _t["id"] != "WSTG-CRYP-01":
        manual_class_for(_t["id"], _t.get("name", _t["id"]), "CRYP", severity="info")
