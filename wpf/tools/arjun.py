from __future__ import annotations

import json
from pathlib import Path

from ._base import ToolWrapper
from .registry import register


@register("arjun")
class Arjun(ToolWrapper):
    binary = "arjun"
    default_timeout = 900.0

    def build_args(self, target: str, **kw) -> list[str]:
        out = Path(kw.get("out_path", "/tmp/arjun.json"))
        return ["arjun", "-u", target, "-oJ", str(out), "-t", str(kw.get("threads", 10))]

    def parse(self, raw, target, **kw) -> list[str]:
        out_path = Path(kw.get("out_path", "/tmp/arjun.json"))
        if not out_path.exists():
            return []
        try:
            data = json.loads(out_path.read_text())
            return data.get(target, {}).get("params", []) or []
        except (json.JSONDecodeError, OSError):
            return []
