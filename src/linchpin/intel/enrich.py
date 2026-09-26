"""Enrich NormalizedFindings with real CVSS / EPSS / KEV data.

Fills gaps only; scanner-reported CVSS is kept unless `prefer_intel=True`.
"""
from __future__ import annotations

from linchpin.intel.store import CveIntel
from linchpin.models import NormalizedFinding


def enrich(findings: list[NormalizedFinding], intel: CveIntel, prefer_intel: bool = False,
           model=None) -> tuple[list[NormalizedFinding], dict]:
    """`model` (optional, linchpin.ml.exploitability.ExploitModel) adds detail.exploitability_learned."""
    out, hit, miss, kev = [], 0, 0, 0
    for f in findings:
        rec = None
        if f.kind == "cve":
            ids = [c for c in [f.cve_id, *((f.detail or {}).get("cves") or [])] if c]
            recs = [r for r in (intel.get(c) for c in dict.fromkeys(ids)) if r is not None]
            # multi-CVE plugin: the most exploitable member drives the edge (KEV first, then EPSS)
            rec = max(recs, key=lambda r: (r.kev, r.epss or 0.0, r.cvss_base or 0.0), default=None)
        if rec is None:
            if f.kind == "cve":
                miss += 1
            out.append(f)
            continue
        hit += 1
        kev += rec.kev
        upd: dict = {}
        if rec.cvss_base is not None and (prefer_intel or f.cvss_base is None):
            upd["cvss_base"] = rec.cvss_base
        if rec.cvss_vector and (prefer_intel or not f.cvss_vector):
            upd["cvss_vector"] = rec.cvss_vector
        if rec.epss is not None and (prefer_intel or f.epss is None):
            upd["epss"] = round(rec.epss, 5)
        detail = dict(f.detail or {})
        detail.update(kev=rec.kev, ransomware=rec.ransomware)
        if rec.cvss_exploitability is not None:
            detail["cvss_exploitability"] = rec.cvss_exploitability
        if rec.kev:
            detail["exploit_maturity"] = "high"
        if not f.cvss_vector and rec.cvss_vector:  # scanner gave no vector: use NVD's
            from linchpin.connectors._common import impact_class
            detail["impact_class"] = impact_class(rec.cvss_vector)
        if rec.kev and detail.get("impact_class") == "info":
            detail["impact_class"] = "rce"  # exploited in the wild beats a vector-based guess
        detail["intel_cve"] = rec.cve
        if model is not None:
            detail["exploitability_learned"] = round(max(model.score(r) for r in recs), 5)
        upd["detail"] = detail
        out.append(f.model_copy(update=upd))
    return out, {"cve_findings": hit + miss, "enriched": hit, "unknown_cve": miss, "kev": kev,
                 "epss_date": intel.meta.get("epss_date", "")}
