from __future__ import annotations

import json

from ._base import ToolWrapper
from .registry import register


@register("dnsx")
class Dnsx(ToolWrapper):
    binary = "dnsx"
    default_timeout = 600.0

    def build_args(self, target: str, **kw) -> list[str]:
        args = ["dnsx", "-silent", "-json", "-a", "-aaaa", "-cname", "-mx", "-ns", "-txt"]
        if kw.get("input_file"):
            args += ["-l", str(kw["input_file"])]
        else:
            args += ["-d", target]
        return args

    def parse(self, raw, target, **kw) -> list[dict]:
        records = []
        for ln in raw.stdout.splitlines():
            ln = ln.strip()
            if ln.startswith("{"):
                try:
                    records.append(json.loads(ln))
                except json.JSONDecodeError:
                    continue
        return records
