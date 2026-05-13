from __future__ import annotations

from ._base import ToolWrapper
from .registry import register


@register("assetfinder")
class Assetfinder(ToolWrapper):
    binary = "assetfinder"

    def build_args(self, target: str, **kw) -> list[str]:
        return ["assetfinder", "--subs-only", target.lstrip("*.")]

    def parse(self, raw, target, **kw) -> list[str]:
        return [ln.strip() for ln in raw.stdout.splitlines() if ln.strip()]
