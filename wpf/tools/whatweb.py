from __future__ import annotations

import json

from ._base import ToolWrapper
from .registry import register


@register("whatweb")
class WhatWeb(ToolWrapper):
    binary = "whatweb"
    default_timeout = 600.0

    def build_args(self, target: str, **kw) -> list[str]:
        return ["whatweb", "--no-errors", "--log-json", "-", "-a", "3", target]

    def parse(self, raw, target, **kw) -> list[dict]:
        out = []
        for ln in raw.stdout.splitlines():
            ln = ln.strip()
            if ln.startswith("{"):
                try:
                    out.append(json.loads(ln))
                except json.JSONDecodeError:
                    continue
        return out
