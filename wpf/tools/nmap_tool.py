from __future__ import annotations

from ._base import ToolWrapper
from .registry import register


@register("nmap")
class Nmap(ToolWrapper):
    binary = "nmap"
    default_timeout = 1800.0

    def build_args(self, target: str, **kw) -> list[str]:
        flags = kw.get("flags", "-sV -Pn -T4 --top-ports 1000")
        args = ["nmap", *flags.split(), "-oN", "-", target]
        return args

    def parse(self, raw, target, **kw) -> str:
        return raw.stdout
