"""OpenVAS / Greenbone GMP XML report parser (``get_reports`` XML export).

One finding per (host, port, NVT). Multi-CVE NVTs keep every CVE in ``detail.cves`` and use a
representative ``cve_id``; NVTs without a CVE get ``detail.vuln_id = "NVT-<oid>"``. Results
below ``min_severity`` (default 4.0) and ``general/*`` pseudo-ports produce no vuln edge but
still register the open service.
"""
from __future__ import annotations

from linchpin.connectors._common import clean, epoch_iso, finding, guess_impact, parse_xml, rep_cve
from linchpin.models import NormalizedFinding

SOURCE = "openvas"


def _tags(s: str | None) -> dict[str, str]:
    out = {}
    for part in (s or "").split("|"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip()] = " ".join(v.split())
    return out


def _port(text: str | None) -> tuple[int | None, str]:
    t = (text or "").strip()
    if "/" not in t:
        return None, "tcp"
    num, proto = t.split("/", 1)
    return (int(num), proto) if num.isdigit() else (None, proto)


def parse(path: str, min_severity: float = 4.0) -> list[NormalizedFinding]:
    root = parse_xml(path)
    rep = root.find("report") if root.find("report") is not None else root
    observed = (rep.findtext("scan_start") or root.findtext("creation_time") or "").strip() or epoch_iso(None)
    out: dict[str, NormalizedFinding] = {}
    for r in rep.iter("result"):
        h = r.find("host")
        if h is None or not (h.text or "").strip():
            continue
        ip = h.text.strip()
        host_id = (h.findtext("hostname") or "").strip() or ip
        port, proto = _port(r.findtext("port"))
        nvt = r.find("nvt")
        if nvt is None:
            continue
        oid = nvt.get("oid", "")
        name = clean(nvt.findtext("name") or r.findtext("name") or "")
        sev = float(r.findtext("severity") or nvt.findtext("cvss_base") or 0)
        tags = _tags(nvt.findtext("tags"))
        vector = tags.get("cvss_base_vector")
        sv = nvt.find("severities/severity/value")
        if sv is not None and sv.text:
            vector = sv.text.strip()
        cves = [ref.get("id") for ref in nvt.iter("ref") if ref.get("type") == "cve" and ref.get("id")]
        epss = nvt.findtext("epss/max_epss/score")
        if port:
            f = finding(host_id, "service", str(port), SOURCE, observed, port=port,
                        detail={"proto": proto, "ip": ip})
            out.setdefault(f.finding_id, f)
        if sev < min_severity or not port:
            continue
        cve = rep_cve(cves)
        key = f"{oid}:{port}"
        detail = {"vuln_id": f"NVT-{oid.rsplit('.', 1)[-1]}", "name": name, "cves": sorted(set(cves)),
                  "family": nvt.findtext("family"), "solution": tags.get("solution"),
                  "solution_type": tags.get("solution_type"), "qod": r.findtext("qod/value"), "ip": ip,
                  "impact_class": guess_impact(vector, name, sev)}
        f = finding(host_id, "cve", key, SOURCE, observed, cve_id=cve, cvss_base=min(sev, 10.0),
                    cvss_vector=vector, epss=float(epss) if epss else None, port=port, detail=detail)
        out[f.finding_id] = f
    return list(out.values())
