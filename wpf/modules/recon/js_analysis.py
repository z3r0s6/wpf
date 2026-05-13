"""JS analysis — endpoint + secret extraction from .js sources."""
from __future__ import annotations

import re
from typing import Iterable

import httpx as _httpx

from ...core.logging import info, warn
from ...core.scope import Scope
from ...core.roi import _SECRET_PATTERNS  # reuse the secret regex catalog


_PATH_RE = re.compile(r"""['"](/[A-Za-z0-9_\-./?=&%+~]{2,200})['"]""")
_URL_RE  = re.compile(r"""['"](https?://[^'"\s]{4,300})['"]""")


async def fetch_js(url: str, *, scope: Scope, timeout: float = 30.0) -> str:
    scope.check_url(url, action="recon.js.fetch")
    async with _httpx.AsyncClient(http2=True, timeout=timeout,
                                  headers={"User-Agent": scope.user_agent}) as client:
        r = await client.get(url, follow_redirects=True)
        r.raise_for_status()
        return r.text


def extract_endpoints(body: str) -> list[str]:
    found = set()
    found.update(_PATH_RE.findall(body))
    found.update(_URL_RE.findall(body))
    return sorted(found)


def extract_secrets(body: str) -> list[tuple[str, str]]:
    hits = []
    for pat, label in _SECRET_PATTERNS:
        for m in pat.finditer(body):
            hits.append((label, m.group(0)[:120]))
    return hits


async def analyse(js_urls: Iterable[str], *, scope: Scope) -> dict[str, dict]:
    """Fetch each JS URL, extract endpoints and any secret-shaped strings."""
    out: dict[str, dict] = {}
    for js in js_urls:
        try:
            body = await fetch_js(js, scope=scope)
        except Exception as e:
            warn(f"js fetch failed: {js}: {e}")
            continue
        out[js] = {
            "endpoints": extract_endpoints(body),
            "secrets": extract_secrets(body),
            "size":     len(body),
        }
    return out
