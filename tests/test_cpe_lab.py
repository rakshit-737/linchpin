"""Offline version -> CVE matching (intel/cpe.py) and the measured-lab analysis on a fixture scan."""
from pathlib import Path

import pytest

from linchpin.connectors import CONNECTORS
from linchpin.intel.cpe import CpeIndex, CpeRow, compare_versions, match_services, parse_cpe

FIX = Path(__file__).parent / "fixtures"


@pytest.mark.parametrize(("a", "b", "want"), [
    ("1.0rc1", "1.0", -1), ("1.0", "1.0.0", 0), ("1.0.0", "1.0.1", -1), ("9.0.30", "9.0.31", -1),
    ("10.1", "9.6.5", 1), ("7.4p1", "7.4", 1), ("9.0.0.M1", "9.0.0", -1), ("5.5.62", "5.5.9", 1),
])
def test_compare_versions(a, b, want):
    assert compare_versions(a, b) == want


def test_parse_cpe_both_formats():
    assert parse_cpe("cpe:/a:igor_sysoev:nginx:1.16.1") == ("igor_sysoev:nginx", "1.16.1", "a")
    assert parse_cpe("cpe:2.3:a:apache:tomcat:9.0.30:*:*:*:*:*:*:*") == ("apache:tomcat", "9.0.30", "a")
    assert parse_cpe("cpe:/a:apache:http_server") == ("apache:http_server", "", "a")
    assert parse_cpe("not-a-cpe") is None


def _row(**kw):
    base = {"vendor_product": "apache:tomcat", "cve": "CVE-2020-1938", "version": "*", "start_incl": "",
            "start_excl": "", "end_incl": "", "end_excl": "", "conditional": False, "cvss_base": 9.8,
            "cvss_vector": None, "cvss_exploitability": None, "epss": 0.9, "kev": True, "impact_class": "rce"}
    return CpeRow(**{**base, **kw})


def test_range_semantics():
    r = _row(start_incl="9.0.0", end_excl="9.0.31")
    assert r.covers("9.0.30") and r.covers("9.0.0") and not r.covers("9.0.31") and not r.covers("8.5.50")
    assert _row(version="2.4.49").covers("2.4.49") and not _row(version="2.4.49").covers("2.4.50")
    assert _row(start_excl="1.0", end_incl="1.2").covers("1.2") and not _row(start_excl="1.0").covers("1.0")


def test_packaged_index_maps_known_kev_cves():
    idx = CpeIndex.load()
    httpd = {r.cve for r in idx.match("apache:http_server", "2.4.49")}
    assert {"CVE-2021-41773", "CVE-2021-42013"} <= httpd
    assert "CVE-2021-41773" not in {r.cve for r in idx.match("apache:http_server", "2.4.51")}
    assert "CVE-2020-1938" in {r.cve for r in idx.match("apache:tomcat", "9.0.30")}  # Ghostcat
    assert "CVE-2020-1938" not in {r.cve for r in idx.match("apache:tomcat", "9.0.31")}
    nginx = idx.match("igor_sysoev:nginx", "1.16.1")  # nmap's vendor name is aliased to NVD's
    assert nginx and all(r.vendor_product in ("f5:nginx", "nginx:nginx") for r in nginx)
    assert "CVE-2022-0543" not in {r.cve for r in idx.match("redis:redis", "5.0.7")}  # Debian-only: conditional


def test_match_services_on_a_real_nmap_export():
    services = CONNECTORS["nmap"](str(FIX / "nmap_vulners.xml"))
    services = [f for f in services if f.kind == "service"]
    found, stats = match_services(services)
    assert stats["identified"] == 1 and len(found) == 1
    f = found[0]
    assert f.detail["match"] == "cpe-range" and f.detail["upgrade"] == "openssh 7.4"
    assert f.cve_id in f.detail["cves"] and f.detail["impact_class"] == "rce"


def test_lab_case_study_replays_the_fixture_scan(tmp_path):
    pytest.importorskip("numpy")
    pytest.importorskip("scipy")
    import importlib.util
    path = Path(__file__).parents[1] / "benchmarks" / "lab_case_study.py"
    spec = importlib.util.spec_from_file_location("lab_case_study", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert mod.main(["--scans", str(FIX / "lab"), "--out", str(tmp_path)]) == 0
    import json
    res = json.loads((tmp_path / "lab_case_study.json").read_text())
    assert all(res["checks"].values())
    assert res["strategies"]["linchpin"]["fixes_to_disconnect"] == 1
    assert res["plan"][0]["action"].startswith("upgrade ")
    topo = (tmp_path / "topology.yaml").read_text()
    assert "dmz+core" in topo and "customer-db" in topo
