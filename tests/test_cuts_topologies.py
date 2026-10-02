import pytest

from linchpin.benchmark import run_one, summarise
from linchpin.engine.cuts import chokepoints, min_remediation_cut
from linchpin.engine.optimizer import recommend
from linchpin.graph.store import GraphStore
from linchpin.synth.topologies import FAMILIES, generate_family, load_pool


def _store(family, seed, n=16):
    f, gt = generate_family(family, n, seed)
    s = GraphStore()
    s.upsert_findings(f)
    s.build_attack_graph()
    return s, gt


def test_pool_is_real_and_committed():
    pool = load_pool()
    assert len(pool["rce"]) > 500 and len(pool["rce_kev"]) > 50
    assert all(r["cve"].startswith("CVE-") for r in pool["info"][:20])
    _, gt = generate_family("single", 12, 0)
    assert gt.cve_pool.startswith("sha256:")


def test_missing_pool_is_an_error_unless_synthetic_is_allowed(tmp_path):
    missing = str(tmp_path / "nope.csv")
    with pytest.raises(FileNotFoundError, match="CVE pool not found"):
        generate_family("single", 12, 0, pool_path=missing)
    with pytest.warns(RuntimeWarning, match="placeholder"):
        findings, gt = generate_family("single", 12, 0, pool_path=missing, allow_synthetic=True)
    assert gt.cve_pool == "synthetic-fallback"
    assert all(f.cve_id.startswith("CVE-2099-") for f in findings if f.kind == "cve")


@pytest.mark.parametrize("family", FAMILIES)
def test_families_are_schema_valid_and_connected(family):
    s, gt = _store(family, 1)
    assert s.reachable_crown_jewels(), family
    assert gt.topology == family


def test_single_family_oracle_agrees_with_planted():
    for seed in range(5):
        s, gt = _store("single", seed)
        assert gt.linchpin in chokepoints(s)
        assert len(min_remediation_cut(s)) == 1
        assert recommend(s, budget=1, k=50)[0].target_node == gt.linchpin


def test_multi_family_has_no_single_cut_but_exact_plan_disconnects():
    for seed in range(4):
        s, _ = _store("multi", seed)
        assert chokepoints(s) == []
        cut = min_remediation_cut(s)
        assert cut and len(cut) >= 2
        recs = recommend(s, budget=len(cut), k=50)
        assert not s.reachable_crown_jewels(exclude=[r.target_node for r in recs])


def test_none_family_min_cut_exceeds_small_budget():
    s, _ = _store("none", 0)
    assert len(min_remediation_cut(s)) > 3


def test_decoys_unreachable_and_never_recommended():
    for fam in FAMILIES:
        s, gt = _store(fam, 2)
        assert gt.decoy_high_cvss in s.g
        assert gt.decoy_high_cvss not in [r.target_node for r in recommend(s, budget=5, k=30)]


def test_benchmark_row_and_summary():
    rows = [run_one(f, 0, 12, budget=3, k=30) for f in ("single", "ad")]
    summ = summarise(rows)
    assert summ["single"]["linchpin"]["disconnect_rate"] == 1.0
    assert summ["single"]["linchpin"]["residual_frac"] <= summ["single"]["cvss"]["residual_frac"]
