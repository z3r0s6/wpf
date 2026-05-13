"""Hidden parameter discovery via arjun + paramspider."""
from __future__ import annotations

from typing import Iterable

from ...core.logging import warn
from ...core.scope import Scope
from ...tools import registry as toolreg


async def discover(urls: Iterable[str], *, scope: Scope) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    arjun = toolreg.get("arjun")
    for url in urls:
        scope.check_url(url, action="recon.params")
        if arjun and arjun.available():
            try:
                res = await arjun.run(url, scope=scope)
                out[url] = res.parsed or []
            except Exception as e:
                warn(f"arjun failed on {url}: {e}")
                out[url] = []
    return out
