"""Chapter 24 — API Hacking.

Looks for common API exposures: Swagger/OpenAPI docs, GraphQL introspection,
unauth endpoints, and well-known REST paths.
"""
from __future__ import annotations

from urllib.parse import urljoin

import httpx as _httpx

from ...core.finding import Finding
from ...core.scope import Scope
from ._shared import BBBWorkflow, register


WELL_KNOWN = ("api-docs", "api/docs", "swagger.json", "swagger/v1/swagger.json",
              "openapi.json", "v2/api-docs", "graphql", "graphiql", "playground",
              "actuator", "actuator/env", "actuator/heapdump", "actuator/mappings",
              "metrics", "trace", ".well-known/openid-configuration")
GQL_INTROSPECT = '{"query": "{__schema{queryType{name}}}"}'


@register
class BBB_ch24(BBBWorkflow):
    key = "ch24_api"
    chapter_number = 24
    title = "API Hacking"

    async def run(self, target: str, *, scope: Scope, **kw) -> list[Finding]:
        base = (target if "://" in target else "https://" + target).rstrip("/")
        scope.check_url(base, action="bbb.ch24")
        findings: list[Finding] = []
        async with _httpx.AsyncClient(timeout=15, http2=True,
                                      headers={"User-Agent": scope.user_agent}, verify=False) as c:
            for p in WELL_KNOWN:
                url = urljoin(base + "/", p)
                try:
                    r = await c.get(url)
                except Exception:
                    continue
                if r.status_code == 200 and ("swagger" in r.text.lower() or "openapi" in r.text.lower() or
                                              "{" in r.text[:100]):
                    findings.append(Finding(
                        code="BBB-API-DOC",
                        title=f"API documentation exposed at /{p}",
                        severity="low", confidence="high",
                        asset=url,
                        description=f"Path /{p} exposes API documentation/metadata — review for sensitive routes.",
                        recommendation="Gate doc routes behind auth in production, or restrict to internal networks.",
                        wstg_id="WSTG-APIT-01", cwe="CWE-200", bbb_chapter=self.key,
                        evidence={"size": len(r.text), "ctype": r.headers.get("content-type", "")},
                    ))
            # GraphQL introspection
            for gp in ("graphql", "api/graphql"):
                url = urljoin(base + "/", gp)
                try:
                    r = await c.post(url, content=GQL_INTROSPECT, headers={"Content-Type": "application/json"})
                except Exception:
                    continue
                if r.status_code == 200 and "__schema" in (r.text or ""):
                    findings.append(Finding(
                        code="BBB-API-GQL-INTROSPECT",
                        title=f"GraphQL introspection enabled at /{gp}",
                        severity="medium", confidence="high",
                        asset=url,
                        description="GraphQL introspection is reachable on this endpoint in production.",
                        recommendation="Disable introspection on production GraphQL servers.",
                        wstg_id="WSTG-APIT-01", cwe="CWE-200", bbb_chapter=self.key,
                    ))
        return findings
