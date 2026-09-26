"""BloodHound ACE edges (v1.2) and the weighted (effort-aware) min cut."""
import json

from linchpin.config import Config
from linchpin.connectors import bloodhound
from linchpin.engine.cuts import chokepoints, fix_cost, min_remediation_cut
from linchpin.engine.optimizer import candidates, recommend
from linchpin.graph.store import GraphStore

DOM = "S-1-5-21-1"


def _u(rid, name, aces=()):
    return {"ObjectIdentifier": f"{DOM}-{rid}", "Properties": {"name": name, "enabled": True},
            "Aces": [{"PrincipalSID": f"{DOM}-{p}", "PrincipalType": "User", "RightName": r} for p, r in aces]}


def _lab(tmp_path):
    users = [_u(1101, "ALICE@LAB.LOCAL"),
             _u(1102, "BOB@LAB.LOCAL", aces=[(1101, "ForceChangePassword")]),
             _u(1103, "CAROL@LAB.LOCAL")]
    groups = [{"ObjectIdentifier": f"{DOM}-1200", "Properties": {"name": "SRVADMINS@LAB.LOCAL"},
               "Members": [], "Aces": [{"PrincipalSID": f"{DOM}-1103", "PrincipalType": "User",
                                        "RightName": "AddMember"}]}]
    computers = [
        {"ObjectIdentifier": f"{DOM}-2001", "Properties": {"name": "WS1.LAB.LOCAL"},
         "Sessions": {"Results": [{"UserSID": f"{DOM}-1101"}]}, "LocalGroups": []},
        {"ObjectIdentifier": f"{DOM}-2002", "Properties": {"name": "SRV.LAB.LOCAL"}, "LocalGroups": [
            {"ObjectIdentifier": f"{DOM}-2002-544",
             "Results": [{"ObjectIdentifier": f"{DOM}-1200", "ObjectType": "Group"}]}]},
        {"ObjectIdentifier": f"{DOM}-1000", "Properties": {"name": "DC.LAB.LOCAL", "isdc": True},
         "LocalGroups": []},
    ]
    domains = [{"ObjectIdentifier": DOM, "Properties": {"name": "LAB.LOCAL"}, "Aces": [
        {"PrincipalSID": f"{DOM}-1102", "PrincipalType": "User", "RightName": "GetChanges"},
        {"PrincipalSID": f"{DOM}-1102", "PrincipalType": "User", "RightName": "GetChangesAll"},
        {"PrincipalSID": f"{DOM}-1103", "PrincipalType": "User", "RightName": "GetChangesAll"}]}]  # half DCSync
    for name, data in [("users", users), ("groups", groups), ("computers", computers), ("domains", domains)]:
        (tmp_path / f"{name}.json").write_text(json.dumps({"data": data, "meta": {"methods": 0}}))
    return tmp_path


def _store(tmp_path, cfg=None):
    fs = bloodhound.parse(str(_lab(tmp_path)))
    s = GraphStore(cfg or Config(entrypoints=["ws1.lab.local"]))
    s.upsert_findings(fs)
    s.build_attack_graph()
    return fs, s


def test_ace_findings(tmp_path):
    fs, _ = _store(tmp_path)
    aces = {(f.detail["principal"], f.detail["target_name"]): f.detail for f in fs if f.detail.get("ace")}
    assert aces[("ALICE@LAB.LOCAL", "BOB@LAB.LOCAL")]["grants_creds"] == ["BOB@LAB.LOCAL"]
    assert aces[("BOB@LAB.LOCAL", "LAB.LOCAL")]["grants_datastores"] == ["ntds@dc.lab.local"]
    assert aces[("CAROL@LAB.LOCAL", "SRVADMINS@LAB.LOCAL")]["grants_hosts"] == ["srv.lab.local"]
    # GetChangesAll without GetChanges is not DCSync
    assert ("CAROL@LAB.LOCAL", "LAB.LOCAL") not in aces


def test_ace_chain_reaches_ntds_and_is_remediable(tmp_path):
    _, s = _store(tmp_path)
    ace = "ace:ALICE@LAB.LOCAL->BOB@LAB.LOCAL"
    assert s.g.edges["cred:ALICE@LAB.LOCAL", ace]["rel"] == "HAS_ACE"
    assert s.g.edges[ace, "cred:BOB@LAB.LOCAL"]["rel"] == "ABUSES"
    assert s.reachable_crown_jewels() == ["ds:ntds@dc.lab.local"]
    assert ace in candidates(s) and ace in chokepoints(s)
    p = s.k_shortest_paths(k=5)[0]
    assert "privesc" in p.stages
    rems = recommend(s, budget=2, k=20)
    assert not s.reachable_crown_jewels(exclude=[r.target_node for r in rems])
    ace_rems = [r for r in rems if r.target_node.startswith("ace:")]
    if ace_rems:
        assert ace_rems[0].action.startswith("remove ")
        assert "abusable AD ACL" in ace_rems[0].rationale


def test_weighted_cut_prefers_cheap_fixes(tmp_path):
    cfg = Config(entrypoints=["ws1.lab.local"], fix_cost={"Credential": 10.0, "Ace": 1.0, "Host": 3.0, "Vuln": 1.0})
    _, s = _store(tmp_path, cfg)
    w = min_remediation_cut(s, weighted=True)
    assert len(w) == 1 and w[0].startswith("ace:")
    assert fix_cost(s, w[0]) == 1.0
    assert len(min_remediation_cut(s)) == 1
    cfg.fix_cost["Ace"] = 50.0  # now rotating a credential is the cheaper cut
    w2 = min_remediation_cut(s, weighted=True)
    assert w2[0].startswith("cred:")


def test_weighted_cut_on_segmentation(tmp_path):
    from linchpin.synth.topologies import generate_family
    f, _ = generate_family("multi", 16, 0)
    s = GraphStore()
    s.upsert_findings(f)
    s.build_attack_graph()
    plain, weighted = min_remediation_cut(s), min_remediation_cut(s, weighted=True)
    eff = lambda cut: sum(fix_cost(s, n) for n in cut)  # noqa: E731
    assert eff(weighted) <= eff(plain)
    assert len(weighted) >= len(plain)
    assert not s.reachable_crown_jewels(exclude=weighted)
