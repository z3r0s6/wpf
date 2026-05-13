"""Screenshot every probed host via gowitness."""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Iterable

from ...core.logging import warn
from ...core.scope import Scope
from ...tools import registry as toolreg


async def screenshot(urls: Iterable[str], *, scope: Scope, out_dir: Path | None = None) -> Path | None:
    wrapper = toolreg.get("gowitness")
    if not wrapper or not wrapper.available():
        warn("gowitness not installed — skipping screenshots")
        return None
    url_list = list(scope.check_hosts([_host_of(u) for u in urls], action="recon.screenshots"))
    if not url_list:
        return None
    out_dir = out_dir or Path("screenshots")
    out_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write("\n".join(urls))
        in_path = Path(fh.name)
    try:
        await wrapper.run("file-input", scope=scope, input_file=in_path, out_dir=out_dir)
        return out_dir
    finally:
        in_path.unlink(missing_ok=True)


def _host_of(url: str) -> str:
    from urllib.parse import urlsplit
    return urlsplit(url).hostname or url
