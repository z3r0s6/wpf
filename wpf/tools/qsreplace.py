"""Pure-Python equivalent of tomnomnom/qsreplace (replaces query-string values).

We keep it in-process rather than shelling out so the BBB XSS workflow can run
without the binary being installed.
"""
from __future__ import annotations

from typing import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def replace(urls: Iterable[str], value: str) -> list[str]:
    out = []
    for u in urls:
        try:
            sp = urlsplit(u)
            if not sp.query:
                continue
            new_q = [(k, value) for k, _v in parse_qsl(sp.query, keep_blank_values=True)]
            out.append(urlunsplit((sp.scheme, sp.netloc, sp.path, urlencode(new_q), sp.fragment)))
        except Exception:
            continue
    return out
