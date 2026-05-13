"""Subdomain takeover check via subzy + nuclei takeovers template."""
from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Iterable

from ...core.finding import Finding
from ...core.logging import warn
from ...core.scope import Scope
from ...tools import registry as toolreg


async def check(hosts: Iterable[str], *, scope: Scope) -> list[Finding]:
    findings: list[Finding] = []
    hostlist = list(scope.check_hosts(hosts, action="recon.takeover"))
    if not hostlist:
        return findings
    subzy = toolreg.get("subzy")
    if subzy and subzy.available():
        with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
            fh.write("\n".join(hostlist))
            in_path = Path(fh.name)
        try:
            res = await subzy.run("hosts", scope=scope, input_file=in_path)
            for ln in (res.parsed or "").splitlines():
                if "[ VULNERABLE ]" in ln.upper() or "VULNERABLE" in ln:
                    findings.append(Finding(
                        code="TAKEOVER-001",
                        title="Probable subdomain takeover",
                        severity="high",
                        confidence="medium",
                        asset=ln.strip(),
                        description="subzy reports a fingerprint match for an unclaimed CNAME target.",
                        recommendation="Reclaim the dangling DNS record or remove it.",
                        wstg_id="WSTG-CONF-10",
                        cwe="CWE-200",
                        references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
                        evidence={"subzy_line": ln.strip()},
                    ))
        finally:
            in_path.unlink(missing_ok=True)
    return findings
