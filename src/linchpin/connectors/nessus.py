"""Tenable Nessus ``.nessus`` (NessusClientData_v2) parser.

One finding per (host, port, pluginID) for severity >= ``min_severity`` (Nessus 0-4 scale,
default 2 = Medium); every ReportItem on a real port also registers the service.
Exploit-availability flags from the plugin are kept in ``detail``.
"""
from __future__ import annotations

from linchpin.connectors._common import epoch_iso, finding, guess_impact, parse_xml, rep_cve
from linchpin.models import NormalizedFinding

SOURCE = "nessus"


def _num(x: str | None) -> float | None:
    try:
        return float(x) if x not in (None, "") else None
    except ValueError:
        return None


def parse(path: str, min_severity: int = 2) -> list[NormalizedFinding]:
    """Parse a ``.nessus`` (v2) report into service and vuln findings at or above ``min_severity``."""
    root = parse_xml(path)
    out: dict[str, NormalizedFinding] = {}
    for rh in root.iter("ReportHost"):
        tags = {t.get("name"): (t.text or "").strip() for t in rh.findall("HostProperties/tag")}
        host_id = tags.get("host-fqdn") or tags.get("netbios-name") or rh.get("name") or tags.get("host-ip")
        observed = epoch_iso(tags.get("HOST_START_TIMESTAMP") or tags.get("HOST_END_TIMESTAMP"))
        os_name = tags.get("operating-system")
        for it in rh.findall("ReportItem"):
            port = int(it.get("port") or 0)
            if port:
                f = finding(host_id, "service", str(port), SOURCE, observed, port=port,
                            service=it.get("svc_name"),
                            detail={"proto": it.get("protocol", "tcp"), "ip": tags.get("host-ip"), "os": os_name})
                out.setdefault(f.finding_id, f)
            sev = int(it.get("severity") or 0)
            if sev < min_severity or not port:
                continue
            cves = [c.text.strip() for c in it.findall("cve") if c.text]
            v3 = it.findtext("cvss3_vector")
            vector = v3 or (it.findtext("cvss_vector") or "").replace("CVSS2#", "") or None
            base = _num(it.findtext("cvss3_base_score")) or _num(it.findtext("cvss_base_score"))
            pid = it.get("pluginID", "0")
            detail = {
                "vuln_id": f"NESSUS-{pid}", "name": it.get("pluginName"), "cves": sorted(set(cves)),
                "family": it.get("pluginFamily"), "solution": " ".join((it.findtext("solution") or "").split()),
                "severity": sev, "exploit_available": (it.findtext("exploit_available") or "").lower() == "true",
                "exploitability_ease": it.findtext("exploitability_ease"),
                "metasploit": (it.findtext("exploit_framework_metasploit") or "").lower() == "true",
                "ip": tags.get("host-ip"), "impact_class": guess_impact(vector, it.get("pluginName"), base),
            }
            if detail["exploit_available"]:
                detail["exploit_maturity"] = "functional" if detail["metasploit"] else "poc"
            f = finding(host_id, "cve", f"{pid}:{port}", SOURCE, observed, cve_id=rep_cve(cves),
                        cvss_base=base, cvss_vector=vector, port=port, detail=detail)
            out[f.finding_id] = f
    return list(out.values())
