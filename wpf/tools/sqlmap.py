"""sqlmap wrapper. Aggressive — requires explicit Scope.aggressive=True."""
from __future__ import annotations

from ._base import ToolResult, ToolWrapper
from .registry import register
from ..core.runner import run_async
from ..core.scope import ScopeError


@register("sqlmap")
class Sqlmap(ToolWrapper):
    binary = "sqlmap"
    default_timeout = 3600.0

    def build_args(self, target: str, **kw) -> list[str]:
        args = ["sqlmap", "--batch", "--random-agent", "--level", str(kw.get("level", 2)),
                "--risk", str(kw.get("risk", 1)), "-u", target]
        if kw.get("data"):
            args += ["--data", kw["data"]]
        if kw.get("cookie"):
            args += ["--cookie", kw["cookie"]]
        if kw.get("threads"):
            args += ["--threads", str(kw["threads"])]
        if kw.get("dbs"):
            args.append("--dbs")
        return args

    async def run(self, target: str, *, scope=None, **kw) -> ToolResult:
        if scope and not scope.aggressive:
            raise ScopeError(
                "sqlmap requires the scope flag 'aggressive: true' (it actively exploits). "
                "Edit your scope.yml or pass an aggressive-enabled scope."
            )
        return await super().run(target, scope=scope, **kw)
