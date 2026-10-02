"""M1 connectors: raw tool exports -> NormalizedFinding[]. Offline file parsers only."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from linchpin.connectors import bloodhound, inventory, native, nessus, nmap, openvas
from linchpin.models import NormalizedFinding

CONNECTORS: dict[str, Callable[[str], list[NormalizedFinding]]] = {
    "json": native.parse,
    "nmap": nmap.parse,
    "openvas": openvas.parse,
    "nessus": nessus.parse,
    "bloodhound": bloodhound.parse,
    "inventory": inventory.parse,
}


def detect(path: str) -> str:
    """Pick a connector by extension and a cheap content sniff."""
    p = Path(path)
    if p.is_dir():
        if bloodhound.is_bloodhound(p):
            return "bloodhound"
        raise ValueError(f"{path}: directory is not a BloodHound collection")
    suf = p.suffix.lower()
    if suf == ".nessus":
        return "nessus"
    if suf in (".yaml", ".yml"):
        return "inventory"
    if suf == ".json":
        return "bloodhound" if bloodhound.is_bloodhound(p) else "json"
    if suf == ".xml":
        head = p.read_bytes()[:8192]
        if b"<nmaprun" in head:
            return "nmap"
        if b"NessusClientData" in head:
            return "nessus"
        if b"<report" in head:
            return "openvas"
    raise ValueError(f"{path}: unrecognised export format")


def parse_any(path: str) -> list[NormalizedFinding]:
    """Parse ``path`` with the connector :func:`detect` picks for it."""
    return CONNECTORS[detect(path)](path)
