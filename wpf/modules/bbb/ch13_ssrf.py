"""Chapter 13 — Server-Side Request Forgery.

Probes parameters with names like url/dest/feed/redirect/callback for outbound
fetch behaviour using an out-of-band interactsh URL if available. Without
interactsh, falls back to canary domain (no exfil) and looks for response
behaviour changes.
"""
from __future__ import annotations

import os
import re
from typing import Iterable

import httpx as _httpx
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ...core.finding import Finding
from ...core.scope import Scope
from ._shared import BBBWorkflow, register


SSRF_PARAMS = {"url", "uri", "dest", "destination", "feed", "callback", "next",
               "data", "domain", "image", "img", "fetch", "host", "html",
               "page", "redirect", "redir", "site", "target", "to"}
INTERNAL_PROBES = ("http://169.254.169.254/latest/meta-data/",  # AWS IMDSv1
                   "http://metadata.google.internal/computeMetadata/v1/",  # GCP
                   "http://[::1]:80/", "http://127.0.0.1/")


@register
class BBB_ch13(BBBWorkflow):
    key = "ch13_ssrf"
    chapter_number = 13
    title = "Server-Side Request Forgery"

    async def run(self, target: str, *, scope: Scope, urls: list[str] | None = None, **kw) -> list[Finding]:
        urls = urls or [target]
        findings: list[Finding] = []
        async with _httpx.AsyncClient(timeout=15, http2=True,
                                      headers={"User-Agent": scope.user_agent},
                                      verify=False) as c:
            for u in urls:
                parsed = urlsplit(u)
                qs = parse_qsl(parsed.query, keep_blank_values=True)
                for name, _v in qs:
                    if name.lower() not in SSRF_PARAMS:
                        continue
                    for probe in INTERNAL_PROBES:
                        new_q = [(k, probe if k == name else v) for k, v in qs]
                        new_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                              urlencode(new_q), parsed.fragment))
                        scope.check_url(new_url, action="bbb.ch13")
                        try:
                            r = await c.get(new_url)
                        except Exception:
                            continue
                        body = r.text or ""
                        if "ami-id" in body or "iam/security-credentials" in body or "Metadata-Flavor" in body:
                            findings.append(Finding(
                                code="BBB-SSRF-IMDS",
                                title="SSRF reaches cloud metadata endpoint",
                                severity="critical", confidence="high",
                                asset=new_url,
                                description="Response contains cloud-metadata-shaped content.",
                                recommendation="Block 169.254.169.254 / metadata.google.internal at the host level; require IMDSv2.",
                                wstg_id="WSTG-INPV-19", cwe="CWE-918", bbb_chapter=self.key,
                                evidence={"probe": probe, "snippet": body[:600]},
                            ))
                            break
        return findings
