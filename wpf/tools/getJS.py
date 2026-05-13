from __future__ import annotations

from ._base import ToolWrapper
from .registry import register


@register("getJS")
class GetJS(ToolWrapper):
    binary = "getJS"
    default_timeout = 600.0

    def build_args(self, target: str, **kw) -> list[str]:
        return ["getJS", "--url", target, "--complete"]

    def parse(self, raw, target, **kw) -> list[str]:
        return [ln.strip() for ln in raw.stdout.splitlines() if ln.strip().startswith("http") and ".js" in ln]
