"""Render findings → Markdown via Jinja2."""
from __future__ import annotations

import datetime as _dt
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from .. import __version__
from ..core.config import AUDIT_LOG_PATH, PKG_TEMPLATES
from ..core.engagement import EngagementContext
from ..core.scope import Scope


def _env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(PKG_TEMPLATES)),
        autoescape=select_autoescape(disabled_extensions=("md.j2", "j2")),
        keep_trailing_newline=True, trim_blocks=False, lstrip_blocks=False,
    )
    return env


def render_markdown(*, scope: Scope, findings: list[dict[str, Any]],
                     targets: list[str], tool_status: list[Any] | None = None,
                     wstg_implemented: int = 0) -> str:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    by_sev: dict[str, list[dict[str, Any]]] = {k: [] for k in counts}
    for f in findings:
        sev = (f.get("severity") or "info").lower()
        counts[sev] = counts.get(sev, 0) + 1
        by_sev.setdefault(sev, []).append({
            **f,
            "evidence":   f.get("evidence") or {},
            "references": f.get("references") or [],
        })
    counts["total"] = sum(counts[k] for k in ("critical", "high", "medium", "low", "info"))

    ctx = EngagementContext.from_scope(scope)
    template = _env().get_template("report.md.j2")
    return template.render(
        engagement={
            "name": ctx.name, "type": ctx.type, "authorized_by": ctx.authorized_by,
            "client": getattr(ctx, "client", "") or "",
            "start": ctx.start, "end": ctx.end,
        },
        scope=scope,
        targets=targets,
        findings=findings,
        findings_by_severity=by_sev,
        counts=counts,
        today=_dt.date.today().isoformat(),
        version=__version__,
        wstg_implemented=wstg_implemented,
        tool_status=tool_status or [],
        audit_log_path=str(AUDIT_LOG_PATH),
    )


def write_markdown(path: Path, body: str) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    return path
