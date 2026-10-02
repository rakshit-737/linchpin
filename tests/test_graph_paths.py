import networkx as nx

from linchpin.engine.paths import node_criticality, rank_paths
from linchpin.graph.store import GraphStore
from linchpin.models import NormalizedFinding, make_finding_id

TS = "2026-01-01T00:00:00Z"


def F(h, kind, key, **kw):
    return NormalizedFinding(finding_id=make_finding_id(h, kind, key), host_id=h, kind=kind,
                             source="t", observed_at=TS, **kw)


def tiny():
    """internet -> web (easy vuln) -> db via (hard vuln) or (cred cached on web)."""
    fs = [
        F("web", "config", "inv", detail={"issue": "inventory", "segment": "dmz", "internet_facing": True}),
        F("db", "config", "inv", detail={"issue": "inventory", "segment": "core",
                                         "datastores": [{"name": "pii", "sensitivity": "high"}]}),
        F("web", "cve", "a", cve_id="CVE-2020-0001", port=80, cvss_base=9.0, epss=0.9),
        F("db", "cve", "b", cve_id="CVE-2020-0002", port=5432, cvss_base=3.0, epss=0.01),
        F("web", "credential", "c", detail={"principal": "dbadmin", "valid_on": ["db"]}),
        F("n", "reachability", "r", detail={"from_segment": "dmz", "to_segment": "core", "ports": [5432]}),
    ]
    s = GraphStore()
    s.upsert_findings(fs)
    s.build_attack_graph()
    return s


def test_build_nodes_and_edges():
    s = tiny()
    for n in ["internet", "host:web", "svc:web:80", "vuln:CVE-2020-0001@web:80", "priv:admin@db",
              "cred:dbadmin", "ds:pii"]:
        assert n in s.g, n
    assert s.g.edges["host:web", "svc:db:5432"]["rel"] == "CAN_REACH"
    assert s.crown_jewels() == ["ds:pii"]
    assert s.entrypoints() == ["internet"]


def test_known_shortest_path_prefers_cred_reuse():
    s = tiny()
    paths = rank_paths(s, k=10)
    assert len(paths) == 2
    assert "cred:dbadmin" in paths[0].nodes
    assert "vuln:CVE-2020-0002@db:5432" in paths[1].nodes
    assert paths[0].total_cost <= paths[1].total_cost
    assert paths[0].nodes[0] == "internet" and paths[0].crown_jewel == "ds:pii"
    assert paths[0].stages[0] == "recon" and paths[0].stages[-1] == "objective"
    assert len(paths[0].stages) == len(paths[0].edges) == len(paths[0].nodes) - 1


def test_no_cross_segment_without_rule():
    s = tiny()
    assert not s.g.has_edge("host:db", "svc:web:80")


def test_criticality_ranks_linchpin_first(synth_store):
    s, gt = synth_store
    crit = node_criticality(rank_paths(s, k=30))
    top_hosts = [n for n in crit if n.startswith("host:")]
    assert top_hosts[0] == gt.linchpin


def test_ground_truth_linchpin_is_a_cut(synth_store):
    s, gt = synth_store
    g = s.g.copy()
    assert nx.has_path(g, "internet", "ds:customer-db")
    g.remove_node(gt.linchpin)
    assert not nx.has_path(g, "internet", "ds:customer-db")


def test_decoy_unreachable(synth_store):
    s, gt = synth_store
    assert gt.decoy_high_cvss in s.g
    assert not nx.has_path(s.g, "internet", gt.decoy_high_cvss)


def test_whatif_does_not_mutate(synth_store):
    s, gt = synth_store
    n_before = s.g.number_of_nodes()
    st = s.remove_nodes_view([gt.linchpin], k=20)
    assert st.paths_before > 0 and st.paths_after == 0
    assert st.reachable_crown_jewels_after == []
    assert s.g.number_of_nodes() == n_before


def test_node_detail(synth_store):
    s, gt = synth_store
    d = s.node(gt.linchpin)
    assert d.label == "Host" and d.props["segment"] == "mgmt"
    assert d.outbound and d.inbound


def test_equal_cost_path_choice_does_not_depend_on_pythonhashseed():
    """Two equally cheap routes plus many unrelated hosts: before the fix, which route Yen returned
    first depended on string-set iteration order (PYTHONHASHSEED)."""
    import subprocess
    import sys
    from pathlib import Path
    code = r'''
import sys
from linchpin.graph.store import GraphStore
from linchpin.models import NormalizedFinding, make_finding_id
def f(h, kind, key, **kw):
    return NormalizedFinding(finding_id=make_finding_id(h, kind, key), host_id=h, kind=kind, source="t",
                             observed_at="2026-01-01T00:00:00Z", **kw)
fs = []
for h in ("web-a", "web-b", "web-c"):
    fs += [f(h, "config", "i", detail={"issue": "inventory", "segment": "dmz", "internet_facing": True}),
           f(h, "service", "80", port=80),
           f(h, "cve", "c", cve_id="CVE-2020-0001", port=80, cvss_base=9.0, epss=0.5),
           f(h, "credential", "k", detail={"principal": "dba", "valid_on": ["db"]})]
fs += [f("db", "config", "i", detail={"issue": "inventory", "segment": "core",
                                      "datastores": [{"name": "crown", "sensitivity": "high"}]})]
fs += [f(f"noise-{i:03d}", "config", "i", detail={"issue": "inventory", "segment": "far"}) for i in range(80)]
s = GraphStore(); s.upsert_findings(fs); s.build_attack_graph()
print([p.path_id for p in s.k_shortest_paths(k=2)])
'''
    src = str(Path(__file__).parents[1] / "src")
    outs = {subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True,
                           env={"PYTHONHASHSEED": str(h), "PYTHONPATH": src, "SYSTEMROOT": "C:\Windows"}).stdout
            for h in (1, 2, 3, 4)}
    assert len(outs) == 1, outs
