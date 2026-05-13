"""amass enum -passive."""
from __future__ import annotations

from ._base import ToolWrapper
from .registry import register


@register("amass")
class Amass(ToolWrapper):
    binary = "amass"
    default_timeout = 1200.0

    def build_args(self, target: str, **kw) -> list[str]:
        args = ["amass", "enum", "-d", target.lstrip("*."), "-nocolor"]
        if kw.get("passive", True):
            args.append("-passive")
        return args

    def parse(self, raw, target, **kw) -> list[str]:
        out = []
        for ln in raw.stdout.splitlines():
            ln = ln.strip()
            # amass enum lines look like "sub.example.com" or "FQDN <-- record -- sub.example.com"
            if ln and not ln.startswith(("OWASP", "[", "Querying", "WARNING")):
                tok = ln.split()[0]
                if "." in tok:
                    out.append(tok)
        return sorted(set(out))
