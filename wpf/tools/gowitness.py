from __future__ import annotations

from pathlib import Path

from ._base import ToolWrapper
from .registry import register


@register("gowitness")
class Gowitness(ToolWrapper):
    binary = "gowitness"
    default_timeout = 1200.0

    def build_args(self, target: str, **kw) -> list[str]:
        out_dir = Path(kw.get("out_dir", "screenshots"))
        out_dir.mkdir(parents=True, exist_ok=True)
        if kw.get("input_file"):
            return ["gowitness", "file", "-f", str(kw["input_file"]),
                    "--screenshot-path", str(out_dir), "-t", "10"]
        return ["gowitness", "single", "-u", target, "--screenshot-path", str(out_dir)]

    def parse(self, raw, target, **kw) -> str:
        return raw.stdout
