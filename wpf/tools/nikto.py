from __future__ import annotations

from ._base import ToolWrapper
from .registry import register


@register("nikto")
class Nikto(ToolWrapper):
    binary = "nikto"
    default_timeout = 3600.0

    def build_args(self, target: str, **kw) -> list[str]:
        return ["nikto", "-h", target, "-ask", "no", "-nointeractive", "-Format", "txt", "-output", "-"]

    def parse(self, raw, target, **kw) -> str:
        return raw.stdout
