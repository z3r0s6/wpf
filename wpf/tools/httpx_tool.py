"""httpx — projectdiscovery HTTP probing."""
from __future__ import annotations

import json

from ._base import ToolResult, ToolWrapper
from .registry import register
from ..core.runner import run_async


@register("httpx")
class HttpxTool(ToolWrapper):
    binary = "httpx"
    default_timeout = 900.0

    def build_args(self, target: str, **kw) -> list[str]:
        args = ["httpx", "-silent", "-json", "-status-code", "-title", "-tech-detect",
                "-content-length", "-server", "-no-color", "-timeout", "10",
                "-threads", str(kw.get("threads", 50)), "-retries", "1"]
        if kw.get("ip"):
            args.append("-ip")
        if kw.get("favicon"):
            args.append("-favicon")
        if kw.get("input_file"):
            args += ["-l", str(kw["input_file"])]
        else:
            args += ["-u", target]
        return args

    def parse(self, raw, target, **kw) -> list[dict]:
        records = []
        for ln in raw.stdout.splitlines():
            ln = ln.strip()
            if not ln or not ln.startswith("{"):
                continue
            try:
                records.append(json.loads(ln))
            except json.JSONDecodeError:
                continue
        return records
