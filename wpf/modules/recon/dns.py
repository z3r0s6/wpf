"""DNS resolution & brute-force stage."""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from ...core.logging import info, warn
from ...core.scope import Scope
from ...tools import registry as toolreg


async def resolve_with_dnsx(hosts: list[str], *, scope: Scope) -> list[dict]:
    """Resolve a list of hosts via dnsx; returns the parsed JSON records."""
    if not hosts:
        return []
    wrapper = toolreg.get("dnsx")
    if not wrapper or not wrapper.available():
        warn("dnsx not installed — skipping DNS resolution")
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(hosts))
        in_path = Path(fh.name)
    try:
        res = await wrapper.run("dnsx", scope=scope, input_file=in_path)
        return res.parsed or []
    finally:
        in_path.unlink(missing_ok=True)


async def brute_force(target: str, *, scope: Scope, wordlist: Path | None = None) -> list[str]:
    """shuffledns brute force (requires massdns + a resolvers file).

    Returns the list of resolved subdomains. No-op if shuffledns isn't installed.
    """
    wrapper = toolreg.get("shuffledns") if "shuffledns" in toolreg.all_names() else None
    if not wrapper:
        warn("shuffledns wrapper not registered; skipping brute force")
        return []
    # Implementation deferred — shuffledns requires a resolvers file and wordlist;
    # see modules/recon/pipeline.py orchestrator for the full plumbing.
    return []
