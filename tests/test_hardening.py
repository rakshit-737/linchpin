"""Input hardening: path confinement by text, per-kind detail validation, graph edge budget."""
import pytest

from linchpin.graph.store import GraphStore, GraphTooLarge
from linchpin.models import NormalizedFinding, detail_problem, make_finding_id
from linchpin.paths_safe import PathNotAllowed, relative_parts, safe_join
from linchpin.synth.topologies import generate_family


@pytest.mark.parametrize("bad", [
    "", "/etc/passwd", r"C:\Windows\win.ini", "C:evil.yaml", r"\\server\share\x.yaml", "//server/share/x",
    "../x.yaml", "a/../../x.yaml", "x.yaml:ads", "NUL", "com1.txt", "trailing.", "x\x00y",
])
def test_relative_parts_refuses_by_text(bad):
    with pytest.raises(PathNotAllowed):
        relative_parts(bad)


def test_safe_join_keeps_paths_inside(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "a.yaml").write_text("x")
    assert safe_join(tmp_path, "sub/a.yaml") == (tmp_path / "sub" / "a.yaml").resolve()
    assert safe_join(tmp_path, r"sub\a.yaml") == (tmp_path / "sub" / "a.yaml").resolve()
    assert safe_join(tmp_path, "./sub//a.yaml") == (tmp_path / "sub" / "a.yaml").resolve()
    with pytest.raises(PathNotAllowed):
        safe_join(tmp_path / "sub", "../a.yaml")


def _f(kind, detail, host="h1"):
    return NormalizedFinding(finding_id=make_finding_id(host, kind, str(detail)), host_id=host, kind=kind,
                             source="t", observed_at="2026-01-01T00:00:00Z", detail=detail)


@pytest.mark.parametrize(("kind", "detail", "ok"), [
    ("credential", {"principal": "svc", "valid_on": ["h2"]}, True),
    ("credential", {}, False),
    ("credential", {"principal": "svc", "valid_on": "h2"}, False),
    ("acl", {"principal": "u", "right": "AdminTo", "target": "h2"}, True),
    ("acl", {"principal": "u", "right": "AdminTo"}, False),
    ("acl", {"principal": "u", "ace": True}, False),
    ("reachability", {"from_segment": "a", "to_segment": "b", "ports": [22]}, True),
    ("reachability", {"from_segment": "a", "to_segment": "b", "ports": ["22"]}, False),
    ("reachability", {"from_segment": "a"}, False),
    ("config", {"issue": "inventory", "datastores": [{"name": "db"}]}, True),
    ("config", {"issue": "inventory", "datastores": ["db"]}, False),
    ("service", {}, True),
])
def test_detail_problem(kind, detail, ok):
    assert (detail_problem(_f(kind, detail)) is None) is ok


def test_build_skips_unusable_findings_and_respects_edge_budget():
    findings, _ = generate_family("none", 30, 0)
    s = GraphStore()
    s.upsert_findings([*findings, _f("credential", {}), _f("reachability", {"from_segment": "x"})])
    stats = s.build_attack_graph()  # no KeyError from the malformed records
    assert stats.edges > 50
    with pytest.raises(GraphTooLarge):
        s.build_attack_graph(max_edges=50)
    assert s.build_attack_graph(max_edges=10 * stats.edges).edges == stats.edges
