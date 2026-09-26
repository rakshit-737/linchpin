"""M1 connectors: raw tool exports -> NormalizedFinding[]. Offline file parsers only."""
from __future__ import annotations

from typing import Callable

from linchpin.connectors import native, nmap
from linchpin.models import NormalizedFinding

CONNECTORS: dict[str, Callable[[str], list[NormalizedFinding]]] = {
    "json": native.parse,
    "nmap": nmap.parse,
}


def parse_any(path: str) -> list[NormalizedFinding]:
    return CONNECTORS["nmap" if path.lower().endswith(".xml") else "json"](path)
