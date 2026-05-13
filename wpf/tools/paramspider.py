from __future__ import annotations

from pathlib import Path

from ._base import ToolWrapper
from .registry import register


@register("paramspider")
class ParamSpider(ToolWrapper):
    binary = "paramspider"
    default_timeout = 600.0

    def build_args(self, target: str, **kw) -> list[str]:
        out = Path(kw.get("out_path", "/tmp/paramspider.txt"))
        return ["paramspider", "-d", target.lstrip("*."), "-o", str(out), "--quiet"]

    def parse(self, raw, target, **kw) -> list[str]:
        out = Path(kw.get("out_path", "/tmp/paramspider.txt"))
        if out.exists():
            return [ln.strip() for ln in out.read_text().splitlines() if ln.strip().startswith("http")]
        return []
