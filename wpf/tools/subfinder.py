"""subfinder — projectdiscovery passive subdomain enum."""
from __future__ import annotations

from ._base import ToolWrapper
from .registry import register


@register("subfinder")
class Subfinder(ToolWrapper):
    binary = "subfinder"

    def build_args(self, target: str, **kw) -> list[str]:
        args = ["subfinder", "-silent", "-d", target.lstrip("*."), "-all"]
        if kw.get("active"):
            args.append("-active")
        return args

    def parse(self, raw, target, **kw) -> list[str]:
        return [ln.strip() for ln in raw.stdout.splitlines() if ln.strip() and "." in ln]
