"""`wpf install` — idempotent multi-method installer.

Methods: apt | go | pipx | git | docker | npm | cargo. The command field in
install_matrix.json is a shell line — we run it through bash with `-eo pipefail`.
Each method has a small pre-flight: apt needs root, go needs the toolchain,
pipx needs pipx, docker needs the daemon. Missing prerequisites short-circuit
to a clear error rather than a half-installed mess.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from ..core.logging import audit, err_console, info, ok, step, warn
from .matrix import load_install_matrix


@dataclass
class InstallResult:
    tool: str
    method: str
    success: bool
    detail: str = ""


def _have(cmd: str) -> bool:
    return shutil.which(cmd) is not None


def _bash(cmd: str, *, sudo_ok: bool = False, timeout: float = 1800.0) -> tuple[int, str]:
    """Run a one-liner through bash. Captures combined output."""
    env = os.environ.copy()
    env["DEBIAN_FRONTEND"] = "noninteractive"
    env["PATH"] = env.get("PATH", "") + ":" + str(Path.home() / "go" / "bin")
    audit("install.cmd", cmd=cmd, sudo_ok=sudo_ok)
    try:
        proc = subprocess.run(
            ["bash", "-eo", "pipefail", "-c", cmd],
            capture_output=True, text=True, timeout=timeout, env=env,
        )
        return proc.returncode, (proc.stdout + proc.stderr).strip()
    except subprocess.TimeoutExpired:
        return -1, f"timeout after {timeout}s"


def _preflight(method: str) -> str | None:
    if method == "apt":
        if not _have("apt"):
            return "apt not present (not a Debian-family system?)"
        if os.geteuid() != 0 and not _have("sudo"):
            return "need root or sudo for apt installs"
    elif method == "go":
        if not _have("go"):
            return "go toolchain missing — run: sudo apt -y install golang-go"
    elif method == "pipx":
        if not _have("pipx"):
            return "pipx missing — run: sudo apt -y install pipx && pipx ensurepath"
    elif method == "git":
        if not _have("git"):
            return "git missing — run: sudo apt -y install git"
    elif method == "docker":
        if not _have("docker"):
            return "docker missing — run: sudo apt -y install docker.io && sudo usermod -aG docker $USER"
    elif method == "npm":
        if not _have("npm"):
            return "npm missing — run: sudo apt -y install npm"
    elif method == "cargo":
        if not _have("cargo"):
            return "cargo missing — run: sudo apt -y install rustc cargo"
    return None


def install_one(tool: str, *, allowed_methods: set[str] | None = None) -> InstallResult:
    matrix = load_install_matrix()
    spec = matrix.get(tool)
    if not spec:
        return InstallResult(tool, "unknown", False, f"no install recipe for {tool!r}")
    method = spec.get("method", "")
    cmd    = spec.get("command", "")
    if allowed_methods and method not in allowed_methods:
        return InstallResult(tool, method, False, f"method {method!r} excluded by --methods")
    err = _preflight(method)
    if err:
        return InstallResult(tool, method, False, err)
    step(f"installing {tool} via {method}")
    rc, out = _bash(cmd)
    if rc == 0:
        post = spec.get("post_install", "").strip()
        if post and not post.startswith("#"):
            rc2, out2 = _bash(post)
            if rc2 != 0:
                return InstallResult(tool, method, True, f"installed but post_install warned: {out2[-200:]}")
        return InstallResult(tool, method, True, "ok")
    return InstallResult(tool, method, False, out[-400:])


def install_many(tools: Iterable[str], *, allowed_methods: set[str] | None = None) -> list[InstallResult]:
    results = []
    for t in tools:
        r = install_one(t, allowed_methods=allowed_methods)
        results.append(r)
        if r.success:
            ok(f"{t}: {r.method} install OK")
        else:
            warn(f"{t}: {r.method} — {r.detail}")
    return results


def install_all(*, allowed_methods: set[str] | None = None) -> list[InstallResult]:
    return install_many(list(load_install_matrix().keys()), allowed_methods=allowed_methods)


# ──────────────────────────────────────────────────────────────────────────
# Curated install bundles. Keep this list small and useful — bundles are a
# starting point, not the whole inventory. `wpf install all` is the full set.
# ──────────────────────────────────────────────────────────────────────────
BUNDLES: dict[str, list[str]] = {
    "passive": [
        "subfinder", "assetfinder", "amass", "gau", "waybackurls",
        "anew", "unfurl", "qsreplace",
    ],
    "recon": [
        "subfinder", "amass", "assetfinder", "findomain", "gau", "waybackurls",
        "dnsx", "httpx", "anew", "unfurl",
    ],
    "probe": [
        "httpx", "dnsx", "naabu", "nmap", "whatweb", "webanalyze", "gowitness",
    ],
    "crawl": [
        "katana", "gospider", "hakrawler", "linkfinder", "getJS", "gau", "waybackurls",
    ],
    "fuzz": [
        "ffuf", "feroxbuster", "dirsearch", "gobuster", "seclists",
    ],
    "xss": [
        "dalfox", "kxss", "Gxss", "qsreplace", "xsstrike",
    ],
    "sqli": [
        "sqlmap", "ghauri",
    ],
    "ssrf": [
        "interactsh-client", "ssrfmap",
    ],
    "ssti": [
        "sstimap",
    ],
    "cors": [
        "corsy", "corscanner",
    ],
    "jwt": [
        "jwt_tool",
    ],
    "cms": [
        "wpscan", "joomscan", "droopescan", "nikto",
    ],
    "takeover": [
        "subzy", "subjack",
    ],
    "params": [
        "arjun", "x8", "paramspider",
    ],
    "vuln": [
        "nuclei", "nuclei-templates",
    ],
    "smuggle": [
        "smuggler", "http2smugl", "h2csmuggler",
    ],
    "cloud": [
        "cloud_enum", "s3scanner", "gcpbucketbrute",
    ],
    "mobile": [
        "apktool", "jadx", "mobsf",
    ],
    "proxy": [
        "mitmproxy", "zaproxy", "proxify",
    ],
}


def resolve_targets(names: list[str]) -> list[str]:
    """Expand bundle names into tool names. Unknown names pass through unchanged
    (the installer will surface a clean error per missing recipe).
    """
    out: list[str] = []
    seen: set[str] = set()
    for n in names:
        for tool in BUNDLES.get(n, [n]):
            if tool not in seen:
                seen.add(tool)
                out.append(tool)
    return out
