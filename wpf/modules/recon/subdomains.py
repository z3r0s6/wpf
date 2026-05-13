"""Subdomain enumeration stage — runs every available passive tool in parallel."""
from __future__ import annotations

import asyncio
from typing import Iterable

from ...core.logging import info, ok, warn
from ...core.scope import Scope
from ...tools import registry as toolreg
from ...tools._base import ToolResult


PASSIVE_TOOLS = ("subfinder", "amass", "assetfinder", "crtsh", "gau", "waybackurls")


async def enumerate_passive(target: str, *, scope: Scope) -> dict[str, list[str]]:
    """Run all available passive subdomain sources against a root domain.

    Returns ``{tool: [subdomains]}``. Tools that aren't installed silently no-op.
    """
    bare = target.lstrip("*.")
    scope.check_host(bare, action="recon.passive.subdomains")
    toolreg.load_all()

    async def run_one(name: str) -> tuple[str, list[str]]:
        wrapper = toolreg.get(name)
        if not wrapper or not wrapper.available():
            warn(f"skip {name}: not installed")
            return name, []
        try:
            info(f"  → {name} {bare}")
            res: ToolResult = await wrapper.run(bare, scope=scope)
            parsed = res.parsed or []
            # Filter wayback / gau to just hostnames
            if name in ("gau", "waybackurls"):
                from urllib.parse import urlsplit
                hosts = set()
                for u in parsed:
                    host = urlsplit(u).hostname
                    if host and (host == bare or host.endswith("." + bare)):
                        hosts.add(host)
                parsed = sorted(hosts)
            ok(f"  ← {name}: {len(parsed)} subdomains")
            return name, sorted(set(parsed))
        except Exception as e:  # pragma: no cover
            warn(f"{name} failed: {e}")
            return name, []

    pairs = await asyncio.gather(*[run_one(t) for t in PASSIVE_TOOLS])
    return dict(pairs)


def consolidate(per_tool: dict[str, Iterable[str]], root: str) -> list[str]:
    """Dedup + normalize + filter to the scope root."""
    root = root.lstrip("*.").lower()
    bag: set[str] = set()
    for _tool, items in per_tool.items():
        for s in items or []:
            s = s.strip().lower().rstrip(".").lstrip("*.")
            if not s or " " in s:
                continue
            if s == root or s.endswith("." + root):
                bag.add(s)
    return sorted(bag)
