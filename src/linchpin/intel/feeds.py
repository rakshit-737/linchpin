"""Parsers for the raw public feeds (NVD CVE JSON 2.0, FIRST EPSS CSV, CISA KEV JSON)."""
from __future__ import annotations

import csv
import gzip
import io
import json
from collections.abc import Iterator
from pathlib import Path

# Max CVSS exploitability sub-score: v3.x = 8.22*0.85*0.77*0.85*0.85 ~= 3.887; v2 = 10.0
EXPL_MAX = {"3": 3.9, "2": 10.0}
_AUTH_TO_PR = {"NONE": "NONE", "SINGLE": "LOW", "MULTIPLE": "HIGH"}


def _open(p: Path):
    p = Path(p)
    return gzip.open(p, "rt", encoding="utf-8") if p.suffix == ".gz" else p.open(encoding="utf-8")


def _pick_metric(metrics: dict) -> tuple[str, dict] | None:
    """Prefer NVD-primary CVSS v3.1 > v3.0 > v2 (v4 publishes no exploitability sub-score)."""
    for key, ver in (("cvssMetricV31", "3"), ("cvssMetricV30", "3"), ("cvssMetricV2", "2")):
        rows = metrics.get(key) or []
        if rows:
            return ver, sorted(rows, key=lambda r: r.get("type") != "Primary")[0]
    return None


def iter_nvd(path: Path) -> Iterator[dict]:
    """Yield one flat record per CVE from an NVD CVE JSON 2.0 feed file (.json or .json.gz)."""
    with _open(path) as fh:
        doc = json.load(fh)
    for item in doc.get("vulnerabilities", []):
        c = item["cve"]
        if c.get("vulnStatus") == "Rejected":
            continue
        desc = next((d["value"] for d in c.get("descriptions", []) if d.get("lang") == "en"), "")
        cwes = sorted({d["value"] for w in c.get("weaknesses", []) for d in w.get("description", [])
                       if d.get("value", "").startswith("CWE-")})
        rec = {"cve": c["id"], "published": c.get("published", "")[:10], "description": desc,
               "cwe": ";".join(cwes), "cvss_version": None, "cvss_base": None, "cvss_vector": None,
               "cvss_exploitability": None, "av": None, "ac": None, "pr": None, "ui": None}
        m = _pick_metric(c.get("metrics", {}))
        if m:
            ver, row = m
            d = row["cvssData"]
            expl = row.get("exploitabilityScore")
            ui = d.get("userInteraction")
            if ui is None:
                ui = "REQUIRED" if row.get("userInteractionRequired") else "NONE"
            rec.update(
                cvss_version=d.get("version"), cvss_base=d.get("baseScore"), cvss_vector=d.get("vectorString"),
                cvss_exploitability=None if expl is None else round(min(expl / EXPL_MAX[ver], 1.0), 4),
                av=d.get("attackVector") or d.get("accessVector"),
                ac=d.get("attackComplexity") or d.get("accessComplexity"),
                pr=d.get("privilegesRequired") or _AUTH_TO_PR.get(d.get("authentication", "")),
                ui=ui,
            )
        yield rec


def load_epss(path: Path) -> tuple[dict[str, float], str]:
    """Return ({cve: epss}, score_date) from a FIRST EPSS CSV (optionally gzipped)."""
    with _open(path) as fh:
        lines = fh.read().splitlines()
    date = ""
    if lines and lines[0].startswith("#"):
        for kv in lines[0][1:].split(","):
            if kv.startswith("score_date:"):
                date = kv.split(":", 1)[1]
        lines = lines[1:]
    return {r["cve"]: float(r["epss"]) for r in csv.DictReader(io.StringIO("\n".join(lines)))}, date


def load_kev(path: Path) -> dict[str, dict]:
    """Return {cve: {date_added, ransomware}} from the CISA KEV JSON catalog."""
    with _open(path) as fh:
        doc = json.load(fh)
    return {v["cveID"]: {"date_added": v.get("dateAdded", ""),
                         "ransomware": v.get("knownRansomwareCampaignUse", "Unknown") == "Known"}
            for v in doc.get("vulnerabilities", [])}
