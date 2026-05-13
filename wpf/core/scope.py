"""Authorization gate.

A YAML scope file under ./scope/ defines in/out scope. Every active probe MUST go
through :func:`check_host` (or :func:`check_url`) before touching the network. An
out-of-scope target raises :class:`ScopeError` and is audit-logged with the caller
identity. There is no override flag for safety — fix the scope file or stop.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import yaml

from .config import PATHS
from .logging import audit


class ScopeError(RuntimeError):
    """Raised when a target lies outside the authorized scope."""


@dataclass
class Engagement:
    name: str = "unnamed"
    type: str = "lab"  # bug_bounty | pentest | lab
    authorized_by: str = ""
    start: str = ""
    end: str = ""


@dataclass
class Scope:
    engagement: Engagement = field(default_factory=Engagement)
    in_scope: list[str] = field(default_factory=list)
    out_scope: list[str] = field(default_factory=list)
    rate_limit_rps: float = 10.0
    aggressive: bool = False
    user_agent: str = "wpf/0.1 (authorized-testing)"
    source_path: Path | None = None

    # ----- file io ----------------------------------------------------------

    @classmethod
    def load(cls, path: Path | str | None = None) -> "Scope":
        path = Path(path) if path else default_scope_path()
        if not path.exists():
            return cls()
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        eng = data.get("engagement") or {}
        flags = data.get("flags") or {}
        return cls(
            engagement=Engagement(**{k: eng.get(k, "") for k in ("name", "type", "authorized_by", "start", "end")}),
            in_scope=list((data.get("scope") or {}).get("in") or []),
            out_scope=list((data.get("scope") or {}).get("out") or []),
            rate_limit_rps=float(flags.get("rate_limit_rps", 10.0)),
            aggressive=bool(flags.get("aggressive", False)),
            user_agent=str(flags.get("user_agent", "wpf/0.1 (authorized-testing)")),
            source_path=path,
        )

    def save(self, path: Path | str | None = None) -> Path:
        path = Path(path) if path else default_scope_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        doc = {
            "engagement": {
                "name": self.engagement.name,
                "type": self.engagement.type,
                "authorized_by": self.engagement.authorized_by,
                "start": self.engagement.start,
                "end": self.engagement.end,
            },
            "scope": {"in": self.in_scope, "out": self.out_scope},
            "flags": {
                "rate_limit_rps": self.rate_limit_rps,
                "aggressive": self.aggressive,
                "user_agent": self.user_agent,
            },
        }
        path.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
        self.source_path = path
        return path

    # ----- mutation --------------------------------------------------------

    def add_in(self, entry: str) -> None:
        if entry not in self.in_scope:
            self.in_scope.append(entry)

    def add_out(self, entry: str) -> None:
        if entry not in self.out_scope:
            self.out_scope.append(entry)

    # ----- matching --------------------------------------------------------

    def is_in_scope(self, host: str) -> bool:
        host = (host or "").strip().lower().rstrip(".")
        if not host:
            return False
        # Explicit out-of-scope wins.
        for rule in self.out_scope:
            if _matches(host, rule):
                return False
        for rule in self.in_scope:
            if _matches(host, rule):
                return True
        return False

    def check_host(self, host: str, *, action: str = "unspecified") -> None:
        if not self.is_in_scope(host):
            audit("scope.refused", host=host, action=action,
                  engagement=self.engagement.name, source=str(self.source_path))
            raise ScopeError(
                f"Host {host!r} is NOT in scope for engagement {self.engagement.name!r}. "
                f"Refusing action {action!r}. Edit {self.source_path or default_scope_path()} to authorize."
            )
        audit("scope.allowed", host=host, action=action, engagement=self.engagement.name)

    def check_url(self, url: str, *, action: str = "unspecified") -> None:
        parsed = urlparse(url if "://" in url else f"//{url}", scheme="https")
        host = parsed.hostname or url
        self.check_host(host, action=action)

    def check_hosts(self, hosts: Iterable[str], *, action: str = "bulk") -> list[str]:
        """Return only the in-scope hosts; non-fatal for bulk lists."""
        allowed, refused = [], []
        for h in hosts:
            if self.is_in_scope(h):
                allowed.append(h)
            else:
                refused.append(h)
        if refused:
            audit("scope.filtered", action=action, refused=refused, engagement=self.engagement.name)
        return allowed


def default_scope_path() -> Path:
    """Path of the active engagement's scope file.

    Each engagement lives in its own file at ``scope/<name>.yml``. The active one
    is exposed at ``scope/scope.yml`` (a symlink). When no symlink exists yet
    (fresh install), we fall back to ``scope/scope.yml`` as a regular file so
    legacy users keep working.
    """
    return PATHS.scope / "scope.yml"


def engagement_path(name: str) -> Path:
    """Filesystem path for the engagement named ``name``."""
    safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in name).strip("._-")
    if not safe:
        raise ValueError(f"invalid engagement name: {name!r}")
    return PATHS.scope / f"{safe}.yml"


def list_engagements() -> list[str]:
    """Return engagement names (the basenames in ``scope/``, sans the active symlink)."""
    out: list[str] = []
    for p in PATHS.scope.glob("*.yml"):
        if p.name in ("scope.yml", "example.scope.yml"):
            continue
        out.append(p.stem)
    return sorted(out)


def active_engagement() -> str | None:
    """Name of the currently-active engagement (what scope.yml points to)."""
    link = default_scope_path()
    if link.is_symlink():
        target = link.resolve()
        if target.exists():
            return target.stem
    if link.exists():
        # Legacy single-file mode — read it and return the embedded name
        try:
            s = Scope.load(link)
            return s.engagement.name or None
        except Exception:
            return None
    return None


def set_active(name: str) -> Path:
    """Make ``scope/<name>.yml`` the active engagement by symlinking scope.yml at it.

    The engagement file must already exist. Returns the symlink path.
    """
    target = engagement_path(name)
    if not target.exists():
        raise FileNotFoundError(f"engagement file does not exist: {target}")
    link = default_scope_path()
    # Replace any existing file/symlink at scope.yml
    if link.exists() or link.is_symlink():
        link.unlink()
    link.symlink_to(target.name)  # relative symlink — portable inside scope/
    return link


def delete_engagement(name: str) -> tuple[Path, bool]:
    """Delete ``scope/<name>.yml`` and unlink the active symlink if it pointed there.

    Returns (path_that_was_removed, was_active_at_removal).
    """
    target = engagement_path(name)
    if not target.exists():
        raise FileNotFoundError(f"no such engagement: {name}")
    was_active = (active_engagement() == name)
    target.unlink()
    link = default_scope_path()
    if was_active and (link.is_symlink() or link.exists()):
        try:
            link.unlink()
        except FileNotFoundError:
            pass
    return target, was_active


# ---------------------------------------------------------------------------
# Rule matching: wildcards (`*.example.com`), bare domains, and CIDR ranges
# ---------------------------------------------------------------------------

_WILDCARD_RE = re.compile(r"^\*\.([a-z0-9._-]+)$")


def _matches(host: str, rule: str) -> bool:
    rule = rule.strip().lower().rstrip(".")
    if not rule:
        return False

    # CIDR?
    if "/" in rule:
        try:
            net = ipaddress.ip_network(rule, strict=False)
            return ipaddress.ip_address(host) in net
        except ValueError:
            pass

    # IP literal?
    try:
        return ipaddress.ip_address(host) == ipaddress.ip_address(rule)
    except ValueError:
        pass

    # Wildcard `*.example.com` — matches subdomains but not the apex.
    m = _WILDCARD_RE.match(rule)
    if m:
        base = m.group(1)
        return host.endswith("." + base)

    # Bare apex `example.com` — matches the apex and any subdomain.
    return host == rule or host.endswith("." + rule)
