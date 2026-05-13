from __future__ import annotations

import json

from ._base import ToolWrapper
from .registry import register


@register("dalfox")
class Dalfox(ToolWrapper):
    binary = "dalfox"
    default_timeout = 1800.0

    def build_args(self, target: str, **kw) -> list[str]:
        args = ["dalfox", "url", target, "--format", "json", "--silence", "--no-color"]
        if kw.get("blind"):
            args += ["-b", kw["blind"]]
        if kw.get("worker"):
            args += ["--worker", str(kw["worker"])]
        return args

    def parse(self, raw, target, **kw) -> list[dict]:
        findings = []
        for ln in raw.stdout.splitlines():
            ln = ln.strip()
            if ln.startswith("{"):
                try:
                    findings.append(json.loads(ln))
                except json.JSONDecodeError:
                    continue
        return findings
