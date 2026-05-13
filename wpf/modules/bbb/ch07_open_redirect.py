"""Chapter 7 — Open Redirects."""
from __future__ import annotations

import httpx as _httpx
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from ...core.finding import Finding
from ...core.scope import Scope
from ._shared import BBBWorkflow, register


REDIRECT_PARAM_NAMES = {"redirect", "redir", "next", "url", "u", "n", "forward",
                        "return", "RelayState", "dest", "destination", "rurl",
                        "checkout_url", "image_url", "go", "out", "view"}
PROBES = ("https://evil.example/x", "//evil.example/x", "https:\\\\evil.example/x",
          "/\\evil.example", "https://evil.example%2F.target.tld")


@register
class BBB_ch07(BBBWorkflow):
    key = "ch07_open_redirect"
    chapter_number = 7
    title = "Open Redirects"

    async def run(self, target: str, *, scope: Scope, urls: list[str] | None = None, **kw) -> list[Finding]:
        urls = urls or [target]
        findings: list[Finding] = []
        async with _httpx.AsyncClient(timeout=10, http2=True,
                                      headers={"User-Agent": scope.user_agent},
                                      verify=False, follow_redirects=False) as c:
            for u in urls:
                parsed = urlsplit(u)
                qs = parse_qsl(parsed.query, keep_blank_values=True)
                for name, _v in qs:
                    if name.lower() not in REDIRECT_PARAM_NAMES:
                        continue
                    for probe in PROBES:
                        new_q = [(k, probe if k == name else v) for k, v in qs]
                        new_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path,
                                              urlencode(new_q), parsed.fragment))
                        scope.check_url(new_url, action="bbb.ch07")
                        try:
                            r = await c.get(new_url)
                        except Exception:
                            continue
                        loc = r.headers.get("Location", "")
                        if 300 <= r.status_code < 400 and "evil.example" in loc:
                            findings.append(Finding(
                                code="BBB-OPEN-REDIRECT",
                                title=f"Open redirect via {name}",
                                severity="medium", confidence="high",
                                asset=new_url,
                                description=f"Server returned {r.status_code} → {loc} for attacker-controlled {name}.",
                                recommendation="Validate redirect targets against an allowlist of relative paths or trusted hosts.",
                                wstg_id="WSTG-CLNT-04", cwe="CWE-601", bbb_chapter=self.key,
                                evidence={"param": name, "probe": probe, "location": loc},
                            ))
                            break
        return findings
