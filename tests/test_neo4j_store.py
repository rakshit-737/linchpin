"""Neo4j adapter: statement generation + push/pull round trip against an in-memory fake
driver. A live-server test runs only when NEO4J_URI and NEO4J_PASSWORD are set."""
import os
import re

import pytest

from linchpin.engine.optimizer import recommend
from linchpin.graph.neo4j_store import Neo4jGraphStore, statements, to_cypher
from linchpin.synth.generator import generate


class FakeSession:
    def __init__(self, db):
        self.db = db

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, q, **p):
        self.db["queries"].append(q)
        if q.startswith("MATCH (n:LinchpinNode {graph: $graph}) DETACH"):
            self.db["nodes"].clear()
            self.db["edges"].clear()
        elif q.startswith("UNWIND") and "MERGE (n:" in q:
            lbl = re.search(r"MERGE \(n:(\w+):LinchpinNode", q).group(1)
            for r in p["rows"]:
                self.db["nodes"][r["id"]] = (lbl, r["props"])
        elif q.startswith("UNWIND") and "MERGE (a)-[e:" in q:
            rel = re.search(r"\[e:(\w+)\]", q).group(1)
            for r in p["rows"]:
                self.db["edges"].append((r["src"], r["dst"], rel, r["props"]))
        elif "RETURN n.id" in q:
            return [{"id": i, "labels": [lbl, "LinchpinNode"], "props": {**pr, "graph": p["graph"], "id": i}}
                    for i, (lbl, pr) in self.db["nodes"].items()]
        elif "RETURN a.id" in q:
            return [{"src": s, "dst": d, "rel": r, "props": pr} for s, d, r, pr in self.db["edges"]]
        return []


class FakeDriver:
    def __init__(self):
        self.db = {"nodes": {}, "edges": [], "queries": []}

    def session(self, database=None):
        return FakeSession(self.db)

    def close(self):
        pass


def _store(driver=None):
    f, gt = generate(14, 5, 3)
    s = Neo4jGraphStore(driver=driver)
    s.upsert_findings(f)
    s.build_attack_graph()
    return s, gt


def test_statements_use_frozen_taxonomy():
    s, _ = _store()
    qs = [q for q, _ in statements(s.g)]
    rels = set(re.findall(r"\[e:(\w+)\]", " ".join(qs)))
    assert rels <= {"RUNS", "HAS_VULN", "ENABLES", "GRANTS", "VALID_ON", "CAN_REACH", "STORED_ON", "LEADS_TO", "HOLDS"}
    assert {"CAN_REACH", "ENABLES", "LEADS_TO", "HOLDS"} <= rels
    assert all("$" not in line for line in to_cypher(s.g).splitlines())


def test_push_pull_roundtrip_preserves_engine_results():
    drv = FakeDriver()
    s, gt = _store(drv)
    before = [r.target_node for r in recommend(s, budget=2, k=30)]
    n_nodes, n_edges = s.g.number_of_nodes(), s.g.number_of_edges()
    s.g = None  # prove engines run on what comes back from "Neo4j"
    s.pull()
    assert (s.g.number_of_nodes(), s.g.number_of_edges()) == (n_nodes, n_edges)
    assert [r.target_node for r in recommend(s, budget=2, k=30)] == before == [gt.linchpin]


@pytest.mark.neo4j
@pytest.mark.skipif(not (os.environ.get("NEO4J_URI") and os.environ.get("NEO4J_PASSWORD")),
                    reason="no Neo4j server configured")
def test_live_neo4j_roundtrip():
    from linchpin.config import Config
    cfg = Config(neo4j={"uri": os.environ["NEO4J_URI"], "user": os.environ.get("NEO4J_USER", "neo4j")})
    s = Neo4jGraphStore.connect(cfg, os.environ["NEO4J_PASSWORD"], graph_name="pytest")
    f, gt = generate(14, 5, 3)
    s.upsert_findings(f)
    s.build_attack_graph()
    s.pull()
    assert recommend(s, budget=1, k=30)[0].target_node == gt.linchpin
    s.close()
