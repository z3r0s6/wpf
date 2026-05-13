from __future__ import annotations

from ._base import ToolWrapper
from .registry import register


@register("naabu")
class Naabu(ToolWrapper):
    binary = "naabu"
    default_timeout = 900.0

    def build_args(self, target: str, **kw) -> list[str]:
        ports = kw.get("ports", "top-1000")
        args = ["naabu", "-silent", "-host", target, "-p", str(ports), "-rate", str(kw.get("rate", 1000))]
        return args

    def parse(self, raw, target, **kw) -> list[str]:
        return [ln.strip() for ln in raw.stdout.splitlines() if ":" in ln]
