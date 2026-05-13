from __future__ import annotations

from ._base import ToolResult, ToolWrapper
from .registry import register
from ..core.runner import run_async


@register("kxss")
class Kxss(ToolWrapper):
    binary = "kxss"
    default_timeout = 1200.0

    def build_args(self, target: str, **kw) -> list[str]:
        return ["kxss"]

    async def run(self, target: str, *, scope=None, urls=None, **kw) -> ToolResult:
        # kxss reads URLs (one per line) on stdin
        stdin = "\n".join(urls or [target]).encode()
        raw = await run_async(self.build_args(target), timeout=self.default_timeout,
                              scope=scope, tool_name=self.binary, input_data=stdin)
        out = []
        for ln in raw.stdout.splitlines():
            if "URL:" in ln and "Param:" in ln:
                out.append(ln.strip())
        return ToolResult(self.binary, target, raw, parsed=out)
