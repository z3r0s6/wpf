"""Rich-formatted console + structured JSONL audit log.

Every authorization decision and every tool launch is appended to
``~/.local/share/wpf/audit.log.jsonl`` for traceability.
"""
from __future__ import annotations

import json
import logging
import sys
import time
from typing import Any

from rich.console import Console
from rich.logging import RichHandler

from .config import AUDIT_LOG_PATH

console = Console(stderr=False, highlight=False, soft_wrap=False)
err_console = Console(stderr=True)


def setup_logging(verbose: int = 0) -> logging.Logger:
    level = logging.WARNING
    if verbose == 1:
        level = logging.INFO
    elif verbose >= 2:
        level = logging.DEBUG
    handler = RichHandler(console=err_console, rich_tracebacks=True, show_path=False, show_time=True, markup=True)
    logging.basicConfig(level=level, handlers=[handler], format="%(message)s", force=True)
    return logging.getLogger("wpf")


def audit(event: str, **fields: Any) -> None:
    """Append a structured event to the audit log. Never raises."""
    try:
        rec = {"ts": time.time(), "event": event, **fields}
        with AUDIT_LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(rec, default=str) + "\n")
    except Exception:  # pragma: no cover
        pass


def banner() -> None:
    from .. import BANNER
    console.print(f"[bold cyan]{BANNER}[/bold cyan]")


def error(msg: str) -> None:
    err_console.print(f"[bold red]error:[/bold red] {msg}")


def warn(msg: str) -> None:
    err_console.print(f"[yellow]warn:[/yellow] {msg}")


def info(msg: str) -> None:
    console.print(f"[cyan]{msg}[/cyan]")


def ok(msg: str) -> None:
    console.print(f"[green]✓[/green] {msg}")


def step(msg: str) -> None:
    console.print(f"[bold blue]▶[/bold blue] {msg}")
