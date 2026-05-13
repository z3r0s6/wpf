"""MD → HTML → PDF using markdown-it-py + WeasyPrint."""
from __future__ import annotations

import base64
import datetime as _dt
from pathlib import Path
from typing import Any

from markdown_it import MarkdownIt

from .. import __version__
from ..core.config import PKG_ASSETS, PKG_THEMES
from ..core.logging import warn


def _md_to_html(md_text: str) -> str:
    md = MarkdownIt("commonmark", {"html": True, "linkify": True, "typographer": True}).enable(["table"])
    return md.render(md_text)


def _cover_html(*, engagement: dict, classification: str, logo_data_uri: str = "") -> str:
    today = _dt.date.today().isoformat()
    return f"""
    <section class="cover">
      <div>
        {f'<img class="logo" src="{logo_data_uri}" alt="logo">' if logo_data_uri else ''}
        <div class="classification">{classification}</div>
      </div>
      <div>
        <h1>{engagement.get('name','wpf')}</h1>
        <div class="sub">Security Assessment Report</div>
      </div>
      <div class="meta">
        <strong>Type:</strong> {engagement.get('type','')} <br/>
        <strong>Client:</strong> {engagement.get('client') or '—'} <br/>
        <strong>Authorized by:</strong> {engagement.get('authorized_by') or '—'} <br/>
        <strong>Period:</strong> {engagement.get('start','?')} → {engagement.get('end','?')} <br/>
        <strong>Generated:</strong> {today} by wpf v{__version__}
      </div>
    </section>
    """


def _wrap_html(body_html: str, *, theme_css: str, cover_html: str) -> str:
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>wpf report</title>
<style>{theme_css}</style></head>
<body>
{cover_html}
{body_html}
</body></html>"""


def _logo_data_uri(logo: Path | None) -> str:
    p = Path(logo) if logo else PKG_ASSETS / "logo.svg"
    if not p.exists():
        return ""
    mime = "image/svg+xml" if p.suffix.lower() == ".svg" else ("image/png" if p.suffix.lower() == ".png"
            else "image/jpeg")
    try:
        data = p.read_bytes()
    except OSError:
        return ""
    return f"data:{mime};base64,{base64.b64encode(data).decode()}"


def render_pdf(md_text: str, *, out_path: Path, engagement: dict,
               theme: str = "corporate", logo: Path | None = None,
               classification: str = "CONFIDENTIAL — Authorized recipients only") -> Path:
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    theme_path = PKG_THEMES / f"{theme}.css"
    if not theme_path.exists():
        theme_path = PKG_THEMES / "corporate.css"
    theme_css = theme_path.read_text(encoding="utf-8")
    cover = _cover_html(engagement=engagement, classification=classification,
                         logo_data_uri=_logo_data_uri(logo))
    body = _md_to_html(md_text)
    html = _wrap_html(body, theme_css=theme_css, cover_html=cover)
    try:
        from weasyprint import HTML
        HTML(string=html, base_url=str(PKG_ASSETS)).write_pdf(target=str(out_path))
        return out_path
    except Exception as e:
        warn(f"WeasyPrint failed ({e}); falling back to HTML-only at {out_path.with_suffix('.html')}")
        out_path.with_suffix(".html").write_text(html, encoding="utf-8")
        return out_path.with_suffix(".html")
