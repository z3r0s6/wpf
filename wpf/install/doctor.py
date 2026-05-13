"""`wpf doctor` — check which tools are installed and ready to run."""
from __future__ import annotations

import shlex
import shutil
import subprocess
from dataclasses import dataclass
from pathlib import Path

from rich.table import Table

from ..core.config import PATHS
from ..core.logging import console
from ..core.runner import which
from .matrix import load_install_matrix, load_tooling_inventory


@dataclass
class ToolStatus:
    name: str
    category: str
    installed: bool
    binary_path: str
    install_hint: str
    method: str


def _quick_check(check_cmd: str, timeout: float = 5.0) -> tuple[bool, str]:
    """Run the matrix's `binary_check` command, capturing exit + first stdout line."""
    if not check_cmd:
        return False, ""
    try:
        proc = subprocess.run(
            ["sh", "-c", check_cmd],
            capture_output=True, text=True, timeout=timeout,
            env={**__import__("os").environ, "PATH": __import__("os").environ.get("PATH", "") + ":" + str(Path.home() / "go" / "bin")},
        )
        installed = (proc.returncode == 0)
        return installed, (proc.stdout or proc.stderr).strip().splitlines()[:1][0] if (proc.stdout or proc.stderr) else ""
    except Exception:
        return False, ""


def status() -> list[ToolStatus]:
    matrix = load_install_matrix()
    inv = {e.get("name"): e for e in load_tooling_inventory()}
    out: list[ToolStatus] = []
    for tool, spec in sorted(matrix.items()):
        binary = which(tool) or shutil.which(tool) or ""
        if not binary:
            ok, _ = _quick_check(spec.get("binary_check", ""))
            installed = ok
        else:
            installed = True
        category = inv.get(tool, {}).get("category", "uncategorized")
        method = spec.get("method", "")
        hint = f"wpf install {tool}" if not installed else ""
        out.append(ToolStatus(tool, category, installed, binary, hint, method))
    return out


def render_table(rows: list[ToolStatus]) -> Table:
    table = Table(title="wpf doctor — tool inventory", show_lines=False)
    table.add_column("Tool", style="bold")
    table.add_column("Category")
    table.add_column("Method")
    table.add_column("Installed")
    table.add_column("Hint")
    n_ok = 0
    for r in rows:
        ok = "[green]✓[/green]" if r.installed else "[red]✗[/red]"
        n_ok += int(r.installed)
        table.add_row(r.name, r.category, r.method, ok, r.install_hint)
    table.caption = f"{n_ok}/{len(rows)} tools available — audit log at {PATHS.data / 'audit.log.jsonl'}"
    return table


def main() -> int:
    rows = status()
    console.print(render_table(rows))
    return 0
