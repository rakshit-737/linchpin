import pytest

from linchpin.benchmark import evaluate, format_p, order, paired_diff, wilson_ci
from linchpin.engine.optimizer import recommend
from linchpin.graph.store import GraphStore
from linchpin.synth.topologies import generate_family


def _store(family="single", n=14, seed=0):
    f, _ = generate_family(family, n, seed)
    s = GraphStore()
    s.upsert_findings(f)
    s.build_attack_graph()
    return s


def test_paired_diff_counts_and_sign_test():
    d = paired_diff([3.0, 2.0, 1.0, 1.0] * 3, [1.0, 1.0, 1.0, 2.0] * 3)
    assert (d["a_larger"], d["b_larger"], d["ties"], d["n"]) == (6, 3, 3, 12)
    assert d["mean_diff"] == pytest.approx(0.5)
    assert d["p_sign"] == pytest.approx(2 * sum((1, 9, 36, 84)) / 2 ** 9)  # exact binomial, 6 vs 3
    assert d["ci95"] is not None and d["ci95"][0] <= 0.5 <= d["ci95"][1]
    assert paired_diff([], []) is None


def test_format_p_and_unrounded_wilson():
    assert format_p(0.0625) == "0.0625" and format_p(2e-6) == "< 1e-4" and format_p(1.0) == "1"
    _, hi = wilson_ci(135, 150, ndigits=None)
    assert round(hi * 100, 1) == 93.8  # not 93.9 from re-rounding 0.9385


def test_patch_only_plan_uses_only_vulns_and_disconnects_single():
    s = _store()
    plan = order(s, "vuln_only", 3)
    assert plan and all(s.g.nodes[n]["label"] == "Vuln" for n in plan)
    assert evaluate(s, plan, 100)["disconnected"]
    assert recommend(s, budget=3, restrict=[]) == []
