from __future__ import annotations

from ._base import ToolWrapper
from .registry import register


@register("subzy")
class Subzy(ToolWrapper):
    binary = "subzy"
    default_timeout = 1200.0

    def build_args(self, target: str, **kw) -> list[str]:
        if kw.get("input_file"):
            return ["subzy", "run", "--targets", str(kw["input_file"]), "--hide_fails", "--vuln"]
        return ["subzy", "run", "--target", target, "--hide_fails", "--vuln"]

    def parse(self, raw, target, **kw) -> str:
        return raw.stdout
