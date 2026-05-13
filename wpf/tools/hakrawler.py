from __future__ import annotations

from ._base import ToolResult, ToolWrapper
from .registry import register
from ..core.runner import run_async


@register("hakrawler")
class Hakrawler(ToolWrapper):
    binary = "hakrawler"
    default_timeout = 600.0

    def build_args(self, target: str, **kw) -> list[str]:
        return ["hakrawler", "-d", str(kw.get("depth", 2)), "-subs", "-u"]

    async def run(self, target: str, *, scope=None, **kw) -> ToolResult:
        raw = await run_async(self.build_args(target, **kw), timeout=self.default_timeout,
                              scope=scope, tool_name=self.binary, input_data=target.encode())
        urls = [ln.strip() for ln in raw.stdout.splitlines() if ln.strip().startswith("http")]
        return ToolResult(self.binary, target, raw, parsed=urls)
