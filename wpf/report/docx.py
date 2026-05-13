"""MD → DOCX via python-docx, with pandoc fallback for better tables."""
from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import Any

from ..core.logging import warn


def _try_pandoc(md_path: Path, out_path: Path) -> bool:
    if not shutil.which("pandoc"):
        return False
    try:
        proc = subprocess.run(
            ["pandoc", "-f", "markdown", "-t", "docx", "-o", str(out_path), str(md_path)],
            capture_output=True, text=True, timeout=120,
        )
        return proc.returncode == 0 and out_path.exists()
    except Exception:
        return False


def _docx_from_markdown(md_text: str, out_path: Path) -> Path:
    """python-docx fallback — handles headings, paragraphs, code blocks, simple tables."""
    from docx import Document
    from docx.shared import Pt

    doc = Document()
    style = doc.styles["Normal"]
    style.font.name = "Calibri"
    style.font.size = Pt(11)

    in_code = False
    code_buf: list[str] = []
    table_buf: list[list[str]] = []

    def flush_table():
        nonlocal table_buf
        if not table_buf:
            return
        cols = max(len(r) for r in table_buf)
        t = doc.add_table(rows=len(table_buf), cols=cols)
        t.style = "Light Grid Accent 1"
        for ri, row in enumerate(table_buf):
            for ci in range(cols):
                t.rows[ri].cells[ci].text = row[ci] if ci < len(row) else ""
        table_buf = []

    for raw in md_text.splitlines():
        line = raw.rstrip()
        if line.startswith("```"):
            if in_code:
                code = "\n".join(code_buf)
                p = doc.add_paragraph()
                run = p.add_run(code)
                run.font.name = "Consolas"; run.font.size = Pt(9)
                code_buf = []; in_code = False
            else:
                flush_table()
                in_code = True
            continue
        if in_code:
            code_buf.append(line)
            continue
        if line.startswith("|") and line.count("|") >= 2:
            cells = [c.strip() for c in line.strip("|").split("|")]
            if all(set(c) <= set("- :") for c in cells):
                continue  # separator row
            table_buf.append(cells)
            continue
        else:
            flush_table()
        if line.startswith("# "):
            doc.add_heading(line[2:].strip(), level=1)
        elif line.startswith("## "):
            doc.add_heading(line[3:].strip(), level=2)
        elif line.startswith("### "):
            doc.add_heading(line[4:].strip(), level=3)
        elif line.startswith("#### "):
            doc.add_heading(line[5:].strip(), level=4)
        elif line.startswith("- "):
            doc.add_paragraph(line[2:].strip(), style="List Bullet")
        elif line.startswith("---"):
            doc.add_paragraph()  # spacer
        elif line.strip() == "":
            doc.add_paragraph()
        else:
            doc.add_paragraph(line)
    flush_table()
    if in_code and code_buf:
        p = doc.add_paragraph("\n".join(code_buf))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(out_path))
    return out_path


def render_docx(md_text: str, *, out_path: Path, md_path: Path | None = None) -> Path:
    out_path = Path(out_path)
    if md_path and _try_pandoc(md_path, out_path):
        return out_path
    return _docx_from_markdown(md_text, out_path)
