import random

import pytest

from linchpin.config import Config, Weights
from linchpin.engine.edge_cost import EdgeContext, edge_cost

CFG = Config()


@pytest.mark.parametrize("ctx,expected", [
    # 0.5*(1-(0.6*1.0+0.4*1.0)) + 0 + 0.2*0.1 = 0.02
    (EdgeContext(rel="ENABLES", transition_class="network_exploit", cvss_base=10, epss=1.0), 0.02),
    # e = 0.6*0.5 + 0.4*0.0 = 0.3 -> 0.5*0.7 + 0.2*0.1 = 0.37
    (EdgeContext(rel="ENABLES", transition_class="network_exploit", cvss_base=5, epss=0.0), 0.37),
    # no epss: e = 0.4 -> 0.3 + 0.02 = 0.32
    (EdgeContext(rel="ENABLES", transition_class="network_exploit", cvss_base=4), 0.32),
    # cred reuse: e = 1 -> 0.2*0.2 = 0.04
    (EdgeContext(rel="GRANTS", transition_class="cred_reuse"), 0.04),
    # structural edge
    (EdgeContext(rel="LEADS_TO"), 0.0),
    # unmet prerequisite: 0.3*1 = 0.3
    (EdgeContext(rel="LEADS_TO", prerequisite_match=0.0), 0.3),
])
def test_table(ctx, expected):
    assert edge_cost(ctx, CFG) == pytest.approx(expected)


def test_higher_exploitability_is_cheaper():
    lo = edge_cost(EdgeContext(rel="ENABLES", cvss_base=3, epss=0.1), CFG)
    hi = edge_cost(EdgeContext(rel="ENABLES", cvss_base=9, epss=0.9), CFG)
    assert hi < lo


def test_property_bounds():
    rng = random.Random(0)
    for _ in range(2000):
        cfg = Config(weights=Weights(w1=rng.random(), w2=rng.random(), w3=rng.random()))
        ctx = EdgeContext(rel=rng.choice(["ENABLES", "GRANTS", "CAN_REACH"]),
                          transition_class=rng.choice([None, "privesc", "client_side"]),
                          cvss_base=rng.choice([None, rng.uniform(0, 10)]),
                          epss=rng.choice([None, rng.random()]),
                          prerequisite_match=rng.random())
        assert 0.0 <= edge_cost(ctx, cfg) <= 1.0


def test_credential_use_needs_network_reachability():
    """Contract v1.3: a credential that only works on an unreachable host costs more to use."""
    from linchpin.graph.store import GraphStore
    from linchpin.models import NormalizedFinding, make_finding_id

    def f(host, kind, key, **kw):
        return NormalizedFinding(finding_id=make_finding_id(host, kind, key), host_id=host, kind=kind,
                                 source="t", observed_at="2026-01-01T00:00:00Z", **kw)

    def inv(host, seg):
        return f(host, "config", "inv", detail={"issue": "inventory", "segment": seg})

    base = [inv("a", "office"), inv("b", "office"), inv("c", "vault"),
            f("a", "service", "445", port=445), f("b", "service", "445", port=445), f("c", "service", "22", port=22),
            f("a", "credential", "svc", detail={"principal": "svc", "valid_on": ["b", "c"]})]
    cfg = Config()
    s = GraphStore(cfg)
    s.upsert_findings(base)
    s.build_attack_graph()
    near = s.g.edges["cred:svc", "priv:admin@b"]
    far = s.g.edges["cred:svc", "priv:admin@c"]
    assert "prerequisite_match" not in near and far["prerequisite_match"] == cfg.prerequisite_penalty
    assert far["cost"] == pytest.approx(near["cost"] + cfg.weights.w2 * (1 - cfg.prerequisite_penalty))
    # an allow rule covering one of c's services makes it reachable again
    rule = f("net", "reachability", "office->vault",
             detail={"from_segment": "office", "to_segment": "vault", "ports": [22]})
    s.upsert_findings([rule])
    s.build_attack_graph()
    assert s.g.edges["cred:svc", "priv:admin@c"]["cost"] == near["cost"]
    # and the check can be switched off
    off = GraphStore(Config(credential_reachability=False))
    off.upsert_findings(base)
    off.build_attack_graph()
    assert off.g.edges["cred:svc", "priv:admin@c"]["cost"] == near["cost"]
