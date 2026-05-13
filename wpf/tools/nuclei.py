from __future__ import annotations

import json

from ._base import ToolWrapper
from .registry import register


@register("nuclei")
class Nuclei(ToolWrapper):
    binary = "nuclei"
    default_timeout = 3600.0

    def build_args(self, target: str, **kw) -> list[str]:
        args = ["nuclei", "-silent", "-jsonl", "-rate-limit", str(kw.get("rate", 150)),
                "-bulk-size", "25", "-c", "25", "-disable-update-check"]
        sev = kw.get("severity")
        if sev:
            args += ["-severity", ",".join(sev) if isinstance(sev, list) else sev]
        tags = kw.get("tags")
        if tags:
            args += ["-tags", ",".join(tags) if isinstance(tags, list) else tags]
        templates = kw.get("templates")
        if templates:
            args += ["-t", ",".join(templates) if isinstance(templates, list) else templates]
        if kw.get("input_file"):
            args += ["-l", str(kw["input_file"])]
        else:
            args += ["-u", target]
        return args

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
