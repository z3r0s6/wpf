"""Name → ToolWrapper class lookup."""
from __future__ import annotations

from typing import Type

from ._base import ToolWrapper

_REGISTRY: dict[str, Type[ToolWrapper]] = {}


def register(name: str):
    def deco(cls: Type[ToolWrapper]) -> Type[ToolWrapper]:
        _REGISTRY[name] = cls
        return cls
    return deco


def get(name: str) -> ToolWrapper | None:
    cls = _REGISTRY.get(name)
    return cls() if cls else None


def all_names() -> list[str]:
    return sorted(_REGISTRY.keys())


# Importing here ensures decorators in each module register at package import time.
def load_all() -> None:
    from . import (  # noqa: F401
        subfinder, amass, assetfinder, crtsh, gau, waybackurls, httpx_tool,
        dnsx, naabu, nmap_tool, katana, gospider, hakrawler, gowitness,
        nuclei, ffuf, arjun, dalfox, sqlmap, subzy, anew, qsreplace,
        whatweb, nikto, wpscan, kxss, getJS, linkfinder, paramspider,
    )
