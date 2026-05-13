from __future__ import annotations

import json

from ._base import ToolWrapper
from .registry import register


@register("wpscan")
class WpScan(ToolWrapper):
    binary = "wpscan"
    default_timeout = 1800.0

    def build_args(self, target: str, **kw) -> list[str]:
        args = ["wpscan", "--url", target, "--format", "json", "--no-update", "--no-banner",
                "--random-user-agent", "--detection-mode", kw.get("mode", "mixed")]
        api = kw.get("api_token")
        if api:
            args += ["--api-token", api]
        if kw.get("enumerate"):
            args += ["-e", kw["enumerate"]]
        return args

    def parse(self, raw, target, **kw) -> dict:
        try:
            return json.loads(raw.stdout)
        except json.JSONDecodeError:
            return {"raw": raw.stdout[-2000:]}
