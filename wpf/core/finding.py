"""Finding dataclass — the canonical unit of pentest output."""
from __future__ import annotations

import hashlib
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class Finding:
    code: str                          # unique short code like 'XSS-REFL-01'
    title: str
    severity: str = "info"             # info|low|medium|high|critical
    cvss: float | None = None
    confidence: str = "medium"         # low|medium|high|confirmed
    asset: str = ""                    # url or host
    description: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)   # raw payloads, requests, response excerpts
    recommendation: str = ""
    references: list[str] = field(default_factory=list)
    wstg_id: str = ""                  # e.g. 'WSTG-INPV-05'
    bbb_chapter: str = ""              # e.g. 'ch06_xss'
    cwe: str = ""                      # e.g. 'CWE-79'
    owasp_top10: str = ""              # e.g. 'A03:2021 - Injection'
    created_at: float = field(default_factory=time.time)
    id: str = field(default_factory=lambda: uuid.uuid4().hex)

    def dedup_key(self) -> str:
        h = hashlib.sha256()
        h.update(self.code.encode())
        h.update(self.asset.encode())
        h.update(self.title.encode())
        h.update(str(sorted(self.evidence.items())).encode())
        return h.hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def severity_rank(self) -> int:
        return SEVERITY_ORDER.get(self.severity, 0)
