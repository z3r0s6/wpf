from __future__ import annotations

import json
from pathlib import Path

from ._base import ToolWrapper
from .registry import register
from ..core.runner import which


@register("linkfinder")
class LinkFinder(ToolWrapper):
    binary = "linkfinder"
    default_timeout = 300.0

    def available(self) -> bool:
        return bool(which("linkfinder")) or Path("/opt/LinkFinder/linkfinder.py").exists()

    def build_args(self, target: str, **kw) -> list[str]:
        if which("linkfinder"):
            return ["linkfinder", "-i", target, "-o", "cli"]
        return ["python3", "/opt/LinkFinder/linkfinder.py", "-i", target, "-o", "cli"]

    def parse(self, raw, target, **kw) -> list[str]:
        return [ln.strip() for ln in raw.stdout.splitlines() if ln.strip()]
