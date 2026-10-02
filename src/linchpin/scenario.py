"""Scenario loader: real exported findings + a declared topology overlay + public exploit intel.

A scenario YAML ties together::

    name: composite-lab
    sources:                       # exported files, relative to --data-dir
      - scans/openvas/many_vuln.xml
      - {path: bloodhound/v6, connector: bloodhound}
    intel: derived/cve_intel.csv.gz   # optional; built by `linchpin intel-build`
    model: derived/exploit_model.npz  # optional M11 model (benchmarks/ml_exploitability.py)
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

CONFIG_KEYS = ("crown_jewels", "entrypoints", "k_shortest", "exploitability_source")


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


def apply_aliases(findings: list[NormalizedFinding], alias: dict[str, str]) -> list[NormalizedFinding]:
    """Rename scanner host ids to their canonical topology ids (``match:`` lists), re-keying ids."""
    return [_rename(f, alias) for f in findings] if alias else list(findings)


def load_scenario(path: str | Path, data_dir: str | Path | None = None, use_intel: bool = True,
                  confine: bool = False) -> tuple[list[NormalizedFinding], Config, dict]:
    """Load a scenario YAML: its exports, the topology overlay and (optionally) exploit intel.

    Args:
        path: the scenario YAML.
        data_dir: base directory for the files it lists (default: the YAML's folder).
        use_intel: enrich CVE findings from the ``intel`` cache when the YAML names one.
        confine: refuse file references that are absolute or escape ``data_dir`` (used when
            the scenario is loaded on behalf of an API caller).

    Returns:
        ``(findings, config, stats)``; ``stats`` counts findings per source, the overlay
        findings, unmatched ``match:`` aliases and intel coverage.

    Raises:
        linchpin.paths_safe.PathNotAllowed: with ``confine=True``, a listed file escapes ``data_dir``.
        FileNotFoundError: a listed export does not exist.
    """
    path = Path(path)
    doc = inventory.load(path)
    base = Path(data_dir) if data_dir else path.parent

    def ref(rel: str) -> Path:
        if confine:
            from linchpin.paths_safe import safe_join
            return safe_join(base, rel)
        return base / rel

    alias = inventory.aliases(doc)
    findings: dict[str, NormalizedFinding] = {}
    per_source: dict[str, int] = {}
    seen_hosts: set[str] = set()
    for src in doc.get("sources", []):
        spec = {"path": src} if isinstance(src, str) else dict(src)
        p = ref(spec["path"])
        name = spec.get("connector") or detect(str(p))
        if name not in CONNECTORS:
            raise ValueError(f"unknown connector {name!r} for {spec['path']} (choose from {sorted(CONNECTORS)})")
        raw = CONNECTORS[name](str(p))
        seen_hosts |= {f.host_id for f in raw}
        got = apply_aliases(raw, alias)
        per_source[spec["path"]] = len(got)
        for f in got:
            findings[f.finding_id] = f
    overlay = inventory.from_doc(doc)
    for f in overlay:
        findings[f.finding_id] = f
    out = sorted(findings.values(), key=lambda f: f.finding_id)
    stats: dict = {"name": doc.get("name", path.stem), "sources": per_source, "findings": len(out),
                   "overlay_findings": len(overlay),
                   "unmatched_aliases": sorted(a for a in alias if a not in seen_hosts)}
    if use_intel and doc.get("intel"):
        ip = ref(doc["intel"])
        if ip.exists():
            from linchpin.intel import CveIntel
            from linchpin.intel.enrich import enrich
            wanted = {c for f in out for c in [f.cve_id, *((f.detail or {}).get("cves") or [])] if c}
            model = None
            if doc.get("model") and ref(doc["model"]).exists():
                from linchpin.ml.exploitability import ExploitModel
                model = ExploitModel.load(ref(doc["model"]))
            out, est = enrich(out, CveIntel.load(ip, only=wanted), model=model)
            est["learned_model"] = model is not None
            stats["intel"] = est
        else:
            stats["intel"] = {"missing": doc["intel"]}
    cfg_over = {k: doc[k] for k in CONFIG_KEYS if k in doc}
    return out, Config(**cfg_over), stats
