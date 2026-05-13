"""Centralized XDG-style paths and runtime config for wpf."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _xdg(env: str, default: Path) -> Path:
    val = os.environ.get(env)
    return Path(val).expanduser() if val else default.expanduser()


@dataclass(frozen=True)
class Paths:
    home:    Path = field(default_factory=lambda: Path.home())
    config:  Path = field(default_factory=lambda: _xdg("XDG_CONFIG_HOME", Path.home() / ".config") / "wpf")
    data:    Path = field(default_factory=lambda: _xdg("XDG_DATA_HOME",   Path.home() / ".local/share") / "wpf")
    cache:   Path = field(default_factory=lambda: _xdg("XDG_CACHE_HOME",  Path.home() / ".cache") / "wpf")
    reports: Path = field(default_factory=lambda: Path.cwd() / "reports")
    scope:   Path = field(default_factory=lambda: Path.cwd() / "scope")

    def ensure(self) -> "Paths":
        for p in (self.config, self.data, self.cache, self.reports, self.scope):
            p.mkdir(parents=True, exist_ok=True)
        (self.data / "tool_runs").mkdir(exist_ok=True)
        (self.data / "evidence").mkdir(exist_ok=True)
        (self.cache / "wordlists").mkdir(exist_ok=True)
        return self


PATHS = Paths().ensure()

# Module-relative paths
PKG_ROOT     = Path(__file__).resolve().parent.parent
PKG_DATA     = PKG_ROOT / "data"
PKG_PAYLOADS = PKG_ROOT / "payloads"
PKG_TEMPLATES = PKG_ROOT / "report" / "templates"
PKG_THEMES   = PKG_ROOT / "report" / "themes"
PKG_ASSETS   = PKG_ROOT / "report" / "assets"

DB_PATH         = PATHS.data / "wpf.db"
AUDIT_LOG_PATH  = PATHS.data / "audit.log.jsonl"
DEFAULT_USER_AGENT = "wpf/0.1 (authorized-testing)"
