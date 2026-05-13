"""Facade: pull findings from the DB and emit MD / PDF / DOCX."""
from __future__ import annotations

import datetime as _dt
from pathlib import Path
from typing import Iterable

from ..core.config import PATHS
from ..core.logging import info, ok
from ..core.scope import Scope
from ..core.store import list_findings, store
from .docx import render_docx
from .markdown import render_markdown, write_markdown
from .pdf import render_pdf


def generate(*, scope: Scope, formats: Iterable[str] = ("md", "pdf", "docx"),
              theme: str = "corporate", logo: Path | None = None,
              out_dir: Path | None = None,
              targets: list[str] | None = None,
              wstg_implemented: int = 0,
              tool_status=None) -> dict[str, Path]:
    out_dir = Path(out_dir or PATHS.reports / scope.engagement.name)
    out_dir.mkdir(parents=True, exist_ok=True)

    with store() as conn:
        row = conn.execute("SELECT id FROM engagements WHERE name=?", (scope.engagement.name,)).fetchone()
        if not row:
            findings: list = []
        else:
            findings = list_findings(conn, row["id"])

    info(f"rendering report for {len(findings)} findings")
    md = render_markdown(scope=scope, findings=findings,
                         targets=targets or [t.value if hasattr(t, "value") else t for t in (targets or [])],
                         tool_status=tool_status, wstg_implemented=wstg_implemented)

    artifacts: dict[str, Path] = {}
    md_path = out_dir / "report.md"
    write_markdown(md_path, md)
    artifacts["md"] = md_path
    ok(f"  → {md_path}")

    eng = {
        "name": scope.engagement.name, "type": scope.engagement.type,
        "client": "", "authorized_by": scope.engagement.authorized_by,
        "start": scope.engagement.start, "end": scope.engagement.end,
    }

    if "pdf" in formats:
        pdf_path = out_dir / "report.pdf"
        artifacts["pdf"] = render_pdf(md, out_path=pdf_path, engagement=eng,
                                      theme=theme, logo=logo)
        ok(f"  → {artifacts['pdf']}")

    if "docx" in formats:
        docx_path = out_dir / "report.docx"
        artifacts["docx"] = render_docx(md, out_path=docx_path, md_path=md_path)
        ok(f"  → {artifacts['docx']}")

    return artifacts
