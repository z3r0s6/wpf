"""crt.sh — no binary; uses httpx HTTP fetch."""
from __future__ import annotations

import asyncio
import httpx as _httpx

from ._base import ToolResult, ToolWrapper
from .registry import register
from ..core.runner import RunResult


@register("crtsh")
class CrtSh(ToolWrapper):
    binary = "curl"  # for availability check only

    def build_args(self, target: str, **kw) -> list[str]:
        return []

    def available(self) -> bool:
        return True

    async def run(self, target: str, *, scope=None, **kw) -> ToolResult:
        bare = target.lstrip("*.")
        if scope:
            scope.check_host(bare, action="crtsh.query")
        url = f"https://crt.sh/?q=%25.{bare}&output=json"
        subs: set[str] = set()
        err = ""
        # crt.sh is HTTP/1.1 only and can be slow on first hit — disable h2, generous timeout,
        # and retry once if the first call returns empty or a transient 5xx.
        for attempt in range(2):
            try:
                async with _httpx.AsyncClient(timeout=120, http2=False,
                                              headers={"User-Agent": "wpf/0.1 ctlog"}) as client:
                    r = await client.get(url)
                    r.raise_for_status()
                    data = r.json()
                if not data:
                    await asyncio.sleep(2)
                    continue
                for entry in data:
                    for name in (entry.get("name_value") or "").splitlines():
                        name = name.strip().lower().lstrip("*.")
                        if name and "." in name and not name.startswith("*"):
                            subs.add(name)
                break
            except Exception as e:  # pragma: no cover
                err = str(e)
                await asyncio.sleep(2)
                continue
        if not subs and err:
            return ToolResult(self.binary, target,
                              RunResult(cmd=f"crtsh:{bare}", returncode=1, stdout="",
                                        stderr=err, duration_s=0.0),
                              parsed=[])
        return ToolResult(self.binary, target,
                          RunResult(cmd=f"crtsh:{bare}", returncode=0,
                                    stdout="\n".join(sorted(subs)), stderr="", duration_s=0.0),
                          parsed=sorted(subs))
