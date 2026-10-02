"""Golden-file tests over trimmed REAL exports (see tests/fixtures/README.md)."""
from pathlib import Path

from linchpin.connectors import CONNECTORS, detect, parse_any
from linchpin.graph.store import GraphStore
from linchpin.scenario import load_scenario

FIX = Path(__file__).parent / "fixtures"


def _schema_ok(fs):
    from linchpin.models import NormalizedFinding
    for f in fs:
        NormalizedFinding.model_validate(f.model_dump())


def test_detect():
    assert detect(str(FIX / "openvas_sample.xml")) == "openvas"
    assert detect(str(FIX / "nessus_sample.nessus")) == "nessus"
    assert detect(str(FIX / "nmap_vulners.xml")) == "nmap"
    assert detect(str(FIX / "bloodhound")) == "bloodhound"
    assert detect(str(FIX / "bloodhound" / "users.json")) == "bloodhound"
    assert detect(str(FIX / "scenario_mini.yaml")) == "inventory"


def test_openvas_golden():
    out = CONNECTORS["openvas"](str(FIX / "openvas_sample.xml"))
    _schema_ok(out)
    vulns = sorted((f.port, f.cve_id, f.detail["vuln_id"], f.detail["impact_class"]) for f in out if f.kind == "cve")
    assert vulns == [
        (22, None, "NVT-105611", "info"),            # weak SSH ciphers: no privilege
        (80, "CVE-2012-2336", "NVT-103482", "info"),
        (512, "CVE-1999-0618", "NVT-100111", "rce"),  # rexec
        (1524, None, "NVT-103549", "rce"),           # ingreslock backdoor, no CVE
    ]
    assert {f.host_id for f in out} == {"b6b9f466d63"}
    assert sorted(f.port for f in out if f.kind == "service") == [22, 80, 512, 1524]
    # finding_id is stable across parses
    assert [f.finding_id for f in out] == [f.finding_id for f in parse_any(str(FIX / "openvas_sample.xml"))]


def test_nessus_golden():
    out = CONNECTORS["nessus"](str(FIX / "nessus_sample.nessus"))
    _schema_ok(out)
    v = [f for f in out if f.kind == "cve"]
    assert len(v) == 1 and v[0].cve_id == "CVE-2012-1823" and v[0].host_id == "testphp.vulnweb.com"
    assert v[0].cvss_vector == "AV:N/AC:L/Au:N/C:P/I:P/A:P" and v[0].detail["vuln_id"] == "NESSUS-58988"
    assert v[0].detail["impact_class"] == "rce"
    assert v[0].detail["exploit_available"] is True


def test_nmap_vulners():
    out = CONNECTORS["nmap"](str(FIX / "nmap_vulners.xml"))
    svc = next(f for f in out if f.kind == "service")
    assert (svc.host_id, svc.port, svc.software, svc.version) == ("192.168.0.1", 5022, "OpenSSH", "7.4")
    cve = next(f for f in out if f.kind == "cve")
    assert cve.detail["cves"] == ["CVE-2017-15906", "CVE-2018-15919"] and cve.cvss_base == 5.0


def test_bloodhound_identity_layer():
    out = parse_any(str(FIX / "bloodhound"))
    _schema_ok(out)
    inv = {f.host_id: f.detail for f in out if f.kind == "config"}
    assert inv["primary.testlab.local"]["is_dc"] and inv["primary.testlab.local"]["datastores"]
    creds = {f.detail["principal"]: f for f in out if f.kind == "credential"}
    da = creds["ADMINISTRATOR@TESTLAB.LOCAL"]
    assert da.host_id == "win10.testlab.local" and da.detail["domain_admin"]
    assert "primary.testlab.local" in da.detail["valid_on"]
    admin_to = {(f.detail["principal"], f.detail["target"]) for f in out
                if f.kind == "acl" and f.detail["right"] == "AdminTo"}
    assert ("DFM@TESTLAB.LOCAL", "win10.testlab.local") in admin_to  # direct local-admin member
    # sibling files alone produce nothing (consumed via computers.json)
    assert parse_any(str(FIX / "bloodhound" / "users.json")) == []


def test_scenario_merges_sources_and_finds_da_path():
    findings, cfg, stats = load_scenario(FIX / "scenario_mini.yaml")
    assert stats["sources"]["openvas_sample.xml"] == 8
    assert {f.host_id for f in findings if f.source == "openvas"} == {"msf2"}  # renamed via match:
    s = GraphStore(cfg)
    s.upsert_findings(findings)
    s.build_attack_graph()
    assert s.crown_jewels() == ["ds:ntds@primary.testlab.local"]
    paths = s.k_shortest_paths()
    assert paths, "internet -> msf2 -> svc_deploy -> win10 -> cached DA hash -> DC"
    p = paths[0]
    assert "cred:ADMINISTRATOR@TESTLAB.LOCAL" in p.nodes and "host:msf2" in p.nodes
    # info-only vulns never grant a privilege
    assert not s.g.has_edge("vuln:NVT-105611@msf2:22", "priv:admin@msf2")
