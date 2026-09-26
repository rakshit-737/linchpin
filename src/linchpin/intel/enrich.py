"""Enrich NormalizedFindings with real CVSS / EPSS / KEV data.

Fills gaps only; scanner-reported CVSS is kept unless `prefer_intel=True`.
"""
from __future__ import annotations

from linchpin.intel.store import CveIntel
from linchpin.models import NormalizedFinding


def enrich(findings: list[NormalizedFinding], intel: CveIntel, prefer_intel: bool = False
           ) -> tuple[list[NormalizedFinding], dict]:
    out, hit, miss, kev = [], 0, 0, 0
    for f in findings:
        rec = intel.get(f.cve_id) if f.kind == "cve" else None
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
        upd["detail"] = detail
        out.append(f.model_copy(update=upd))
    return out, {"cve_findings": hit + miss, "enriched": hit, "unknown_cve": miss, "kev": kev,
                 "epss_date": intel.meta.get("epss_date", "")}
