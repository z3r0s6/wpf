from __future__ import annotations

from ._base import ToolWrapper
from .registry import register


@register("gau")
class Gau(ToolWrapper):
    binary = "gau"
    default_timeout = 600.0

    def build_args(self, target: str, **kw) -> list[str]:
        args = ["gau", "--threads", "5", "--subs", target.lstrip("*.")]
        if kw.get("providers"):
            args += ["--providers", ",".join(kw["providers"])]
        return args

    def parse(self, raw, target, **kw) -> list[str]:
        return [ln.strip() for ln in raw.stdout.splitlines() if ln.strip().startswith("http")]
