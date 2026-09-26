from pathlib import Path

import pytest

from linchpin.config import Config
from linchpin.engine.edge_cost import EdgeContext, edge_cost, exploitability
from linchpin.intel import CveIntel
from linchpin.intel.enrich import enrich
from linchpin.models import NormalizedFinding, make_finding_id

FIX = Path(__file__).parent / "fixtures" / "intel"


@pytest.fixture(scope="module")
def intel(tmp_path_factory):
    out = tmp_path_factory.mktemp("intel") / "cve_intel.csv.gz"
    built = CveIntel.build(FIX, out)
    assert len(built) == 3  # rejected CVE dropped
    return CveIntel.load(out)


def test_roundtrip_fields(intel):
    r = intel.get("CVE-2021-44228")
    assert r.kev and r.ransomware and r.cvss_base == 10.0 and r.cvss_exploitability == 1.0
    assert r.epss == pytest.approx(0.99999) and r.av == "NETWORK"
    v2 = intel.get("CVE-2011-2523")
    assert v2.cvss_exploitability == 1.0 and v2.pr == "NONE" and not v2.kev
    assert intel.get("CVE-2020-0001").cvss_exploitability == pytest.approx(0.5 / 3.9, abs=1e-4)
    assert intel.meta["epss_date"].startswith("2026-09-25")


def _cve(cve, cvss=None):
    return NormalizedFinding(finding_id=make_finding_id("h", "cve", cve), host_id="h", kind="cve", cve_id=cve,
                             cvss_base=cvss, port=80, source="test", observed_at="2026-01-01T00:00:00Z")


def test_enrich_fills_gaps_keeps_scanner_cvss(intel):
    out, stats = enrich([_cve("CVE-2021-44228", cvss=9.0), _cve("CVE-2020-0001"), _cve("CVE-2000-0001")], intel)
    assert out[0].cvss_base == 9.0 and out[0].detail["kev"] is True and out[0].epss > 0.99
    assert out[1].cvss_base == 6.7 and out[1].detail["kev"] is False
    assert stats == {"cve_findings": 3, "enriched": 2, "unknown_cve": 1, "kev": 1,
                     "epss_date": "2026-09-25T12:03:13Z"}


def test_kev_floor_and_subscore_preference():
    base = EdgeContext(rel="ENABLES", transition_class="network_exploit", cvss_base=6.7, epss=0.0004)
    sub = base.model_copy(update={"cvss_exploitability": 0.13})
    kev = sub.model_copy(update={"kev": True})
    assert exploitability(sub) < exploitability(base)  # local/high-complexity => harder than base/10 says
    assert exploitability(kev) == 0.95
    cfg = Config()
    assert edge_cost(kev, cfg) < edge_cost(sub, cfg)
    # v1.0 behaviour unchanged when the new inputs are absent
    assert exploitability(base) == pytest.approx(0.6 * 0.67 + 0.4 * 0.0004)
