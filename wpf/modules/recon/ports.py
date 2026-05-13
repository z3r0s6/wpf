"""Port scan stage — naabu by default, nmap as backup."""
from __future__ import annotations

import asyncio
from typing import Iterable

from ...core.logging import info, warn
from ...core.scope import Scope
from ...tools import registry as toolreg


async def scan_host(host: str, *, scope: Scope, ports: str = "top-1000") -> list[str]:
    scope.check_host(host, action="recon.ports.naabu")
    wrapper = toolreg.get("naabu")
    if wrapper and wrapper.available():
        res = await wrapper.run(host, scope=scope, ports=ports)
        return res.parsed or []
    wrapper = toolreg.get("nmap")
    if wrapper and wrapper.available():
        res = await wrapper.run(host, scope=scope)
        return [res.parsed or ""]
    warn("neither naabu nor nmap installed — skipping port scan")
    return []


async def scan_many(hosts: Iterable[str], *, scope: Scope, ports: str = "top-1000",
                    concurrency: int = 4) -> dict[str, list[str]]:
    sem = asyncio.Semaphore(concurrency)
    out: dict[str, list[str]] = {}

    async def one(h):
        async with sem:
            out[h] = await scan_host(h, scope=scope, ports=ports)

    await asyncio.gather(*[one(h) for h in hosts])
    return out
