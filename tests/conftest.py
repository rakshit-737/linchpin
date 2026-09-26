import pytest

from linchpin.graph.store import GraphStore
from linchpin.synth.generator import generate


@pytest.fixture
def synth_store():
    findings, gt = generate(20, 5, 0)
    s = GraphStore()
    s.upsert_findings(findings)
    s.build_attack_graph()
    return s, gt
