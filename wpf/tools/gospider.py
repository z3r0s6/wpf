from __future__ import annotations

from ._base import ToolWrapper
from .registry import register


@register("gospider")
class Gospider(ToolWrapper):
    binary = "gospider"
    default_timeout = 900.0

    def build_args(self, target: str, **kw) -> list[str]:
        args = ["gospider", "-s", target, "-d", str(kw.get("depth", 2)), "-c", "10", "-t", "10",
                "--no-redirect", "--js", "--robots", "--sitemap"]
        return args

    def parse(self, raw, target, **kw) -> list[str]:
        urls = set()
        for ln in raw.stdout.splitlines():
            tok = ln.strip()
            if " - http" in tok:
                urls.add(tok.split(" - ", 1)[1].strip())
            elif tok.startswith("http"):
                urls.add(tok)
        return sorted(urls)
