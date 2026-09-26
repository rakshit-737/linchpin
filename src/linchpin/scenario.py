"""Scenario loader: real exported findings + a declared topology overlay + public exploit intel.

A scenario YAML ties together::

    name: composite-lab
    sources:                       # exported files, relative to --data-dir
      - scans/openvas/many_vuln.xml
      - {path: bloodhound/v6, connector: bloodhound}
    intel: derived/cve_intel.csv.gz   # optional; built by `linchpin intel-build`
    hosts: [...]                   # topology overlay (see connectors/inventory.py)
    reachability: [...]
    credentials: [...]
    crown_jewels: ["auto:sensitivity=high"]   # optional config overrides
    entrypoints: ["auto:internet_facing"]

Scanner host ids listed under a host's `match:` are renamed to that host's `id`, so findings
from different tools about the same machine merge onto one node.
"""
from __future__ import annotations

from pathlib import Path

from linchpin.config import Config
from linchpin.connectors import CONNECTORS, detect, inventory
from linchpin.models import NormalizedFinding, make_finding_id


def _rename(f: NormalizedFinding, alias: dict[str, str]) -> NormalizedFinding:
    d = dict(f.detail or {})
    for key in ("target",):
        if key in d and d[key] in alias:
            d[key] = alias[d[key]]
    if "valid_on" in d:
        d["valid_on"] = [alias.get(h, h) for h in d["valid_on"]]
    hid = alias.get(f.host_id, f.host_id)
    if hid == f.host_id and d == f.detail:
        return f
    # re-key so the stable id reflects the canonical host
    key = f.finding_id if hid == f.host_id else make_finding_id(hid, f.kind, f.finding_id)
    return f.model_copy(update={"host_id": hid, "detail": d, "finding_id": key})


def load_scenario(path: str | Path, data_dir: str | Path | None = None, use_intel: bool = True
                  ) -> tuple[list[NormalizedFinding], Config, dict]:
    path = Path(path)
    doc = inventory.load(path)
    base = Path(data_dir) if data_dir else path.parent
    alias = inventory.aliases(doc)
    findings: dict[str, NormalizedFinding] = {}
    per_source: dict[str, int] = {}
    for src in doc.get("sources", []):
        spec = {"path": src} if isinstance(src, str) else dict(src)
        p = base / spec["path"]
        name = spec.get("connector") or detect(str(p))
        got = [_rename(f, alias) for f in CONNECTORS[name](str(p))]
        per_source[spec["path"]] = len(got)
        for f in got:
            findings[f.finding_id] = f
    for f in inventory.from_doc(doc):
        findings[f.finding_id] = f
    out = sorted(findings.values(), key=lambda f: f.finding_id)
    stats: dict = {"name": doc.get("name", path.stem), "sources": per_source, "findings": len(out)}
    if use_intel and doc.get("intel"):
        ip = base / doc["intel"]
        if ip.exists():
            from linchpin.intel import CveIntel
            from linchpin.intel.enrich import enrich
            wanted = {c for f in out for c in [f.cve_id, *((f.detail or {}).get("cves") or [])] if c}
            out, est = enrich(out, CveIntel.load(ip, only=wanted))
            stats["intel"] = est
        else:
            stats["intel"] = {"missing": str(ip)}
    cfg_over = {k: doc[k] for k in ("crown_jewels", "entrypoints", "k_shortest") if k in doc}
    return out, Config(**cfg_over), stats
