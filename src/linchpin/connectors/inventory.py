"""Host-inventory / topology overlay (YAML or JSON) -> inventory + reachability findings.

Scanner exports know hosts and services but not *where* a host sits, what it holds or what
the firewall allows. This file supplies that context::

    hosts:
      - id: web-01
        match: [192.168.1.10, testphp.vulnweb.com]   # scanner host ids to rename to `id`
        segment: dmz
        internet_facing: true
        os: linux
        datastores: [{name: customer-db, sensitivity: high}]
    reachability:
      - {from: dmz, to: internal, ports: [445, 3389]}   # empty ports = any
    credentials:
      - {principal: svc_backup, cred_type: password, stored_on: web-01, valid_on: [db-01]}

`aliases(path)` returns the scanner-id -> id rename map used by :mod:`linchpin.scenario`.
"""
from __future__ import annotations

import json
from pathlib import Path

import yaml

from linchpin.connectors._common import finding
from linchpin.models import NormalizedFinding

SOURCE = "inventory"
TS = "1970-01-01T00:00:00+00:00"


def load(path: str | Path) -> dict:
    """Read a topology / inventory document (YAML, or JSON by extension)."""
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    return (json.loads(text) if p.suffix == ".json" else yaml.safe_load(text)) or {}


def is_inventory(path: str | Path) -> bool:
    """True if ``path`` is a YAML document with a ``hosts`` list."""
    p = Path(path)
    if p.suffix.lower() not in (".yaml", ".yml"):
        return False
    try:
        doc = load(p)
    except Exception:
        return False
    return isinstance(doc, dict) and "hosts" in doc


def aliases(path_or_doc) -> dict[str, str]:
    """Scanner host id -> canonical host id, from every host's ``match:`` list."""
    doc = path_or_doc if isinstance(path_or_doc, dict) else load(path_or_doc)
    out = {}
    for h in doc.get("hosts", []):
        for m in h.get("match", []) or []:
            out[str(m)] = h["id"]
    return out


def parse(path: str) -> list[NormalizedFinding]:
    """Inventory, reachability and credential findings of a topology file."""
    return from_doc(load(path))


def from_doc(doc: dict) -> list[NormalizedFinding]:
    """Inventory, reachability and credential findings of an already-loaded topology document."""
    out: list[NormalizedFinding] = []
    for h in doc.get("hosts", []):
        d = {"issue": "inventory", "severity": "low", "datastores": h.get("datastores", [])}
        d.update({k: h[k] for k in ("segment", "os", "internet_facing", "role") if k in h})
        out.append(finding(h["id"], "config", "overlay", SOURCE, TS, detail=d))
    for r in doc.get("reachability", []):
        a, b = r["from"], r["to"]
        out.append(finding("net", "reachability", f"{a}->{b}", SOURCE, TS, detail={
            "from_segment": a, "to_segment": b, "ports": r.get("ports") or [], "allowed": r.get("allowed", True)}))
    for c in doc.get("credentials", []):
        out.append(finding(c["stored_on"], "credential", c["principal"], SOURCE, TS, detail={
            "principal": c["principal"], "cred_type": c.get("cred_type", "password"),
            "valid_on": c.get("valid_on", [])}))
    return out
