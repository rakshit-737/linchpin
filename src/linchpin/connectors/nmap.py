"""nmap -oX parser (stdlib ElementTree; defusedxml recommended for untrusted input)."""
from __future__ import annotations

import xml.etree.ElementTree as ET

from linchpin.models import NormalizedFinding, make_finding_id


def parse(path: str) -> list[NormalizedFinding]:
    root = ET.parse(path).getroot()
    observed = "1970-01-01T00:00:00+00:00" if not root.get("start") else _epoch(root.get("start"))
    out: list[NormalizedFinding] = []
    for h in root.findall("host"):
        addr = h.find("address")
        if addr is None:
            continue
        host_id = addr.get("addr")
        hn = h.find("hostnames/hostname")
        if hn is not None and hn.get("name"):
            host_id = hn.get("name")
        for p in h.findall("ports/port"):
            st = p.find("state")
            if st is None or st.get("state") != "open":
                continue
            port = int(p.get("portid"))
            s = p.find("service")
            out.append(NormalizedFinding(
                finding_id=make_finding_id(host_id, "service", str(port)), host_id=host_id, kind="service",
                port=port, service=s.get("name") if s is not None else None,
                software=s.get("product") if s is not None else None,
                version=s.get("version") if s is not None else None,
                detail={"proto": p.get("protocol")}, source="nmap", observed_at=observed))
    return out


def _epoch(s: str) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(int(s), tz=timezone.utc).isoformat()
