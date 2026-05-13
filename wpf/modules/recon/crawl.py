"""Crawling + URL discovery stage."""
from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

from ...core.logging import info, warn
from ...core.scope import Scope
from ...tools import registry as toolreg


async def crawl_one(url: str, *, scope: Scope, depth: int = 3) -> dict[str, list[str]]:
    scope.check_url(url, action="recon.crawl")
    out: dict[str, list[str]] = {}
    for tool in ("katana", "gospider", "hakrawler"):
        wrapper = toolreg.get(tool)
        if not wrapper or not wrapper.available():
            continue
        try:
            info(f"  crawler: {tool} {url}")
            res = await wrapper.run(url, scope=scope, depth=depth)
            out[tool] = res.parsed or []
        except Exception as e:  # pragma: no cover
            warn(f"{tool} failed on {url}: {e}")
            out[tool] = []
    return out


async def crawl_many(urls: list[str], *, scope: Scope, depth: int = 2,
                      concurrency: int = 3) -> dict[str, dict[str, list[str]]]:
    sem = asyncio.Semaphore(concurrency)
    aggregated: dict[str, dict[str, list[str]]] = {}

    async def one(u):
        async with sem:
            aggregated[u] = await crawl_one(u, scope=scope, depth=depth)

    await asyncio.gather(*[one(u) for u in urls])
    return aggregated
