"""HTTP probing stage — wrap httpx with input-file mode."""
from __future__ import annotations

import tempfile
from pathlib import Path

from ...core.logging import info, warn
from ...core.scope import Scope
from ...tools import registry as toolreg


async def probe(hosts: list[str], *, scope: Scope) -> list[dict]:
    """Send hosts to httpx, return parsed JSON records."""
    if not hosts:
        return []
    wrapper = toolreg.get("httpx")
    if not wrapper or not wrapper.available():
        warn("httpx not installed — skipping HTTP probe")
        return []
    in_scope = scope.check_hosts(hosts, action="recon.http_probe")
    if not in_scope:
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(in_scope))
        in_path = Path(fh.name)
    try:
        res = await wrapper.run("httpx", scope=scope, input_file=in_path)
        return res.parsed or []
    finally:
        in_path.unlink(missing_ok=True)
