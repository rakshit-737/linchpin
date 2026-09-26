"""Real-data tests: run only when the public datasets have been downloaded
(python scripts/download_data.py; python -m linchpin intel-build). Point LINCHPIN_DATA_DIR at
the dataset directory if it is not ../../datasets/linchpin relative to the repo."""
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DATA = Path(os.environ.get("LINCHPIN_DATA_DIR", ROOT / ".." / ".." / "datasets" / "linchpin"))
INTEL = DATA / "derived" / "cve_intel.csv.gz"

pytestmark = [pytest.mark.realdata,
              pytest.mark.skipif(not (DATA / "scans").exists(), reason="real datasets not downloaded")]


def test_all_real_exports_parse():
    from linchpin.connectors import parse_any
    counts = {p.name: len(parse_any(str(p))) for p in sorted((DATA / "scans").glob("*/*"))}
    assert counts["many_vuln.xml"] > 40 and counts["nessus_with_cvssv3.nessus"] > 20


@pytest.mark.skipif(not INTEL.exists(), reason="intel cache not built")
def test_composite_case_study_headline():
    from linchpin.engine.cuts import min_remediation_cut
    from linchpin.engine.optimizer import recommend
    from linchpin.graph.store import GraphStore
    from linchpin.scenario import load_scenario
    f, cfg, stats = load_scenario(ROOT / "scenarios" / "composite_lab.yaml", DATA)
    assert stats["intel"]["enriched"] >= 40 and stats["intel"]["kev"] >= 1
    s = GraphStore(cfg)
    s.upsert_findings(f)
    s.build_attack_graph()
    top = recommend(s, budget=3, k=100)[0]
    assert top.residual_paths == 0 and not s.reachable_crown_jewels(exclude=[top.target_node])
    assert len(min_remediation_cut(s)) == 1


@pytest.mark.skipif(not INTEL.exists(), reason="intel cache not built")
def test_intel_known_values():
    from linchpin.intel import CveIntel
    i = CveIntel.load(INTEL, only={"CVE-2021-44228", "CVE-2012-1823"})
    assert i.get("CVE-2021-44228").kev and i.get("CVE-2021-44228").cvss_base == 10.0
    assert i.get("CVE-2012-1823").kev
