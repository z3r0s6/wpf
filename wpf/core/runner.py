"""Subprocess runner with scope gating, rate limiting, timeouts, and structured persistence."""
from __future__ import annotations

import asyncio
import os
import shlex
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Sequence

from .config import PATHS
from .logging import audit, err_console, info, warn
from .scope import Scope


@dataclass
class RunResult:
    cmd: str
    returncode: int
    stdout: str
    stderr: str
    duration_s: float
    stdout_path: Path | None = None
    stderr_path: Path | None = None
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


def which(binary: str) -> str | None:
    """`shutil.which` but also searches $HOME/go/bin and /opt/*/."""
    p = shutil.which(binary)
    if p:
        return p
    go_bin = Path(os.environ.get("GOBIN") or os.path.expanduser("~/go/bin"))
    cand = go_bin / binary
    if cand.exists() and os.access(cand, os.X_OK):
        return str(cand)
    return None


def _evidence_paths(tool: str) -> tuple[Path, Path]:
    base = PATHS.data / "tool_runs" / f"{tool}-{int(time.time()*1000)}"
    base.mkdir(parents=True, exist_ok=True)
    return base / "stdout.txt", base / "stderr.txt"


def _check_scope_for(args: Sequence[str], scope: Scope | None) -> None:
    """Naively scan args for hostnames; refuse if any obvious host is out-of-scope.

    The scan looks for tokens that look like hostnames or URLs. False negatives are
    possible — every dedicated tool wrapper SHOULD also call scope.check_host()
    explicitly before invoking run(). This is a belt-and-braces safety net.
    """
    if scope is None:
        return
    for a in args:
        if not isinstance(a, str):
            continue
        if "://" in a:
            try:
                scope.check_url(a, action="run")
            except Exception:
                raise
        elif "." in a and "/" not in a and " " not in a and len(a) < 256:
            # crude hostname guess
            host = a.split(":")[0].rstrip(".")
            if host and host[0].isalnum() and all(c.isalnum() or c in ".-_" for c in host):
                try:
                    scope.check_host(host, action="run")
                except Exception:
                    raise


async def run_async(args: Sequence[str], *, timeout: float = 600.0, env: dict | None = None,
                    cwd: Path | str | None = None, input_data: bytes | None = None,
                    scope: Scope | None = None, capture: bool = True,
                    tool_name: str | None = None, persist: bool = True) -> RunResult:
    """Run a subprocess. Refuses out-of-scope hosts when a Scope is supplied."""
    if shutil.which(args[0]) is None and which(args[0]) is None:
        raise FileNotFoundError(f"binary not found in PATH: {args[0]}")
    _check_scope_for(args, scope)
    full_env = os.environ.copy()
    full_env["PATH"] = full_env.get("PATH", "") + ":" + os.path.expanduser("~/go/bin")
    if env:
        full_env.update(env)

    audit("run.start", tool=tool_name or args[0], cmd=" ".join(shlex.quote(a) for a in args))
    t0 = time.time()
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE if input_data is not None else None,
        stdout=asyncio.subprocess.PIPE if capture else None,
        stderr=asyncio.subprocess.PIPE if capture else None,
        env=full_env, cwd=str(cwd) if cwd else None,
    )
    timed_out = False
    try:
        stdout_b, stderr_b = await asyncio.wait_for(
            proc.communicate(input_data), timeout=timeout
        )
    except asyncio.TimeoutError:
        timed_out = True
        try:
            proc.kill()
        finally:
            stdout_b, stderr_b = b"", b""
    dt = time.time() - t0

    stdout = (stdout_b or b"").decode("utf-8", "replace")
    stderr = (stderr_b or b"").decode("utf-8", "replace")
    sp = ep = None
    if persist:
        sp, ep = _evidence_paths(tool_name or args[0])
        sp.write_text(stdout)
        ep.write_text(stderr)
    audit("run.done", tool=tool_name or args[0], rc=proc.returncode, dur=dt, timed_out=timed_out)
    return RunResult(
        cmd=" ".join(shlex.quote(a) for a in args),
        returncode=proc.returncode if not timed_out else -1,
        stdout=stdout, stderr=stderr, duration_s=dt,
        stdout_path=sp, stderr_path=ep, timed_out=timed_out,
    )


def run(args: Sequence[str], **kwargs) -> RunResult:
    """Synchronous wrapper."""
    return asyncio.run(run_async(args, **kwargs))


# ---------- bounded parallel fanout -----------------------------------------

async def gather_bounded(coros: Iterable, *, limit: int = 8):
    sem = asyncio.Semaphore(limit)

    async def _bound(c):
        async with sem:
            return await c

    return await asyncio.gather(*[_bound(c) for c in coros], return_exceptions=True)
