from __future__ import annotations

from ._base import ToolWrapper
from .registry import register


@register("katana")
class Katana(ToolWrapper):
    binary = "katana"
    default_timeout = 900.0

    def build_args(self, target: str, **kw) -> list[str]:
        args = ["katana", "-silent", "-jc", "-jsl", "-kf", "all", "-depth", str(kw.get("depth", 3)),
                "-concurrency", "10", "-rate-limit", "100"]
        if kw.get("headless"):
            args.append("-headless")
        if kw.get("input_file"):
            args += ["-l", str(kw["input_file"])]
        else:
            args += ["-u", target]
        return args

    def parse(self, raw, target, **kw) -> list[str]:
        return [ln.strip() for ln in raw.stdout.splitlines() if ln.strip().startswith("http")]
