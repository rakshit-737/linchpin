"""nmap ``-oX`` parser.

Open services (product, version, CPE, OS guess) become ``service`` findings. When the
``vulners`` NSE script ran, its CVE list becomes one ``cve`` finding per service (all CVEs kept
in ``detail.cves``); without it, ``linchpin ingest --match-cpe`` maps versions to CVEs offline.
"""
from __future__ import annotations

from linchpin.connectors._common import epoch_iso, finding, parse_xml, rep_cve
from linchpin.models import NormalizedFinding

SOURCE = "nmap"


def _vulners(port_el) -> list[tuple[str, float | None, bool]]:
    out = []
    for script in port_el.findall("script"):
        if script.get("id") != "vulners":
            continue
        for tbl in script.iter("table"):
            elems = {e.get("key"): (e.text or "") for e in tbl.findall("elem")}
            if elems.get("type") == "cve" and elems.get("id", "").startswith("CVE-"):
                try:
                    cvss = float(elems.get("cvss", ""))
                except ValueError:
                    cvss = None
                out.append((elems["id"], cvss, elems.get("is_exploit") == "true"))
    return out


def parse(path: str) -> list[NormalizedFinding]:
    """Parse nmap ``-oX`` output: open services (product, version, CPE) and ``vulners`` CVEs if present."""
    root = parse_xml(path)
    observed = epoch_iso(root.get("start"))
    out: list[NormalizedFinding] = []
    for h in root.findall("host"):
        st = h.find("status")
        if st is not None and st.get("state") not in (None, "up"):
            continue
        addr = h.find("address")
        if addr is None:
            continue
        ip = addr.get("addr")
        host_id = ip
        hn = h.find("hostnames/hostname")
        if hn is not None and hn.get("name"):
            host_id = hn.get("name")
        osm = h.find("os/osmatch")
        os_name = osm.get("name") if osm is not None else None
        for p in h.findall("ports/port"):
            pst = p.find("state")
            if pst is None or pst.get("state") != "open":
                continue
            port = int(p.get("portid"))
            s = p.find("service")
            detail = {"proto": p.get("protocol"), "ip": ip}
            if os_name:
                detail["os"] = os_name
            cpe = s.findtext("cpe") if s is not None else None
            if cpe:
                detail["cpe"] = cpe
            out.append(finding(
                host_id, "service", str(port), SOURCE, observed, port=port,
                service=s.get("name") if s is not None else None,
                software=s.get("product") if s is not None else None,
                version=s.get("version") if s is not None else None, detail=detail))
            vul = _vulners(p)
            if vul:
                cves = sorted({c for c, _, _ in vul})
                best = max((c for _, c, _ in vul if c is not None), default=None)
                out.append(finding(
                    host_id, "cve", f"vulners:{port}", SOURCE, observed, cve_id=rep_cve(cves), port=port,
                    cvss_base=best, software=s.get("product") if s is not None else None,
                    version=s.get("version") if s is not None else None,
                    detail={"vuln_id": f"VULNERS-{port}", "cves": cves, "ip": ip,
                            "name": f"{len(cves)} CVEs matched by vulners.nse for {cpe or 'service'}",
                            "exploit_available": any(x for _, _, x in vul)}))
    return out
