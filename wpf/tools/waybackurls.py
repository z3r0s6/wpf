from __future__ import annotations

import asyncio

from ._base import ToolResult, ToolWrapper
from .registry import register
from ..core.runner import run_async


@register("waybackurls")
class Waybackurls(ToolWrapper):
    binary = "waybackurls"
    default_timeout = 600.0

    def build_args(self, target: str, **kw) -> list[str]:
        return ["waybackurls", target.lstrip("*.")]

    async def run(self, target: str, *, scope=None, **kw) -> ToolResult:
        # waybackurls reads stdin too; build_args handles single-domain mode.
        raw = await run_async(self.build_args(target), timeout=self.default_timeout,
                              scope=scope, tool_name=self.binary)
        urls = [ln.strip() for ln in raw.stdout.splitlines() if ln.strip().startswith("http")]
        return ToolResult(self.binary, target, raw, parsed=urls)
