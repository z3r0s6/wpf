from __future__ import annotations

import json
from pathlib import Path

from ._base import ToolWrapper
from .registry import register


@register("ffuf")
class Ffuf(ToolWrapper):
    binary = "ffuf"
    default_timeout = 1800.0

    def build_args(self, target: str, **kw) -> list[str]:
        wordlist = kw.get("wordlist", "/usr/share/seclists/Discovery/Web-Content/common.txt")
        if not Path(wordlist).exists():
            wordlist = "/usr/share/seclists/Discovery/Web-Content/raft-small-words.txt"
        url = target if "FUZZ" in target else target.rstrip("/") + "/FUZZ"
        return ["ffuf", "-u", url, "-w", wordlist, "-mc", kw.get("match_codes", "200,204,301,302,307,401,403,500"),
                "-of", "json", "-o", "-", "-t", str(kw.get("threads", 40)), "-rate", str(kw.get("rate", 60)),
                "-s"]

    def parse(self, raw, target, **kw) -> list[dict]:
        try:
            data = json.loads(raw.stdout)
            return data.get("results", [])
        except json.JSONDecodeError:
            return []
