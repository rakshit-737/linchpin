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


def test_xml_with_entity_declarations_is_refused(tmp_path):
    import pytest

    from linchpin.connectors._common import parse_xml
    bomb = tmp_path / "bomb.xml"
    bomb.write_text('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;">]><r>&b;</r>')
    with pytest.raises(ValueError, match="refused unsafe XML"):
        parse_xml(bomb)
    late = tmp_path / "late.xml"  # the old stdlib fallback only looked at the first 4 KiB
    late.write_text('<?xml version="1.0"?><!-- ' + "x" * 5000 + ' --><!DOCTYPE r [<!ENTITY x "X">]><r>&x;</r>')
    with pytest.raises(ValueError):
        parse_xml(late)
