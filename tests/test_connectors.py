import json
from pathlib import Path

from linchpin.connectors import CONNECTORS, parse_any

FIX = Path(__file__).parent / "fixtures"


def test_nmap_golden():
    out = CONNECTORS["nmap"](str(FIX / "nmap_sample.xml"))
    assert [(f.host_id, f.port, f.service, f.software) for f in out] == [
        ("lab-web", 22, "ssh", "OpenSSH"), ("lab-web", 80, "http", "nginx")]
    assert all(f.kind == "service" and f.source == "nmap" for f in out)
    assert out[0].finding_id == parse_any(str(FIX / "nmap_sample.xml"))[0].finding_id


def test_native_drops_invalid(tmp_path):
    good = dict(finding_id="a", host_id="h", kind="service", port=1, source="x",
                observed_at="2026-01-01T00:00:00Z")
    p = tmp_path / "f.json"
    p.write_text(json.dumps([good, {**good, "kind": "bogus"}]))
    assert len(parse_any(str(p))) == 1
