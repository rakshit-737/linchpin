import pytest

from linchpin.benchmark import run
from linchpin.engine.explain import explain_path
from linchpin.engine.optimizer import recommend
from linchpin.graph.store import GraphStore
from linchpin.synth.generator import generate


def test_linchpin_picked_first(synth_store):
    s, gt = synth_store
    recs = recommend(s, budget=3)
    assert recs[0].target_node == gt.linchpin
    assert recs[0].residual_paths == 0
    assert recs[0].coverage_pct == 100.0
    assert len(recs) == 1  # a full cut ends the search


def test_every_remediation_explained(synth_store):
    s, _ = synth_store
    for r in recommend(s, budget=3):
        assert r.rationale and r.evidence


def test_rationale_snapshot(synth_store):
    s, _ = synth_store
    r = recommend(s, budget=1)[0]
    assert r.rationale == (
        "host:jump-01 (segment mgmt) is the only pivot from dmz to internal; add segmentation rule "
        f"isolating jump-01 breaks {r.paths_broken}/{r.paths_total} enumerated attack paths to ds:customer-db.")


def test_explain_path(synth_store):
    s, _ = synth_store
    p = s.k_shortest_paths(k=1)[0]
    txt = explain_path(p, s)
    assert txt.startswith(f"Path {p.path_id}") and "ds:customer-db" in txt


def test_does_not_patch_decoy(synth_store):
    s, gt = synth_store
    assert gt.decoy_high_cvss not in [r.target_node for r in recommend(s, budget=5)]


@pytest.mark.parametrize("seed", range(20))
def test_top1_matches_ground_truth_across_seeds(seed):
    f, gt = generate(10 + seed * 2, 5, seed)
    s = GraphStore()
    s.upsert_findings(f)
    s.build_attack_graph()
    assert recommend(s, budget=1, k=50)[0].target_node == gt.linchpin


def test_beats_cvss_baseline_small():
    res = run(n_topologies=5, budget=2, k=30)
    assert res["top1_accuracy"] == 1.0
    assert res["mean_residual_linchpin"] < res["mean_residual_cvss"]
