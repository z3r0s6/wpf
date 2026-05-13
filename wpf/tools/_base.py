"""Tool wrapper ABC.

Every wrapper:
1. Declares ``binary`` (the executable name).
2. Reports ``available()`` (do we have the binary?).
3. Implements ``async run(target, **kwargs) -> ToolResult`` which builds args,
   delegates to :func:`wpf.core.runner.run_async`, and parses the output.

The wrapper never decides scope — that's runner.run_async's job (it's given the
Scope) — but wrappers SHOULD call ``scope.check_host`` before doing network IO
unrelated to subprocess (e.g., crt.sh HTTP fetches).
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ..core.runner import RunResult, run_async, which


@dataclass
class ToolResult:
    tool: str
    target: str
    raw: RunResult
    parsed: Any = None
    artifacts: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.raw.ok


class ToolWrapper(ABC):
    binary: str = ""
    default_timeout: float = 600.0

    def available(self) -> bool:
        return which(self.binary) is not None

    @abstractmethod
    def build_args(self, target: str, **kwargs) -> list[str]:
        ...

    def parse(self, raw: RunResult, target: str, **kwargs) -> Any:
        return raw.stdout

    async def run(self, target: str, *, scope=None, **kwargs) -> ToolResult:
        args = self.build_args(target, **kwargs)
        raw = await run_async(args, timeout=kwargs.pop("timeout", self.default_timeout),
                              scope=scope, tool_name=self.binary)
        parsed = self.parse(raw, target, **kwargs)
        return ToolResult(tool=self.binary, target=target, raw=raw, parsed=parsed)
