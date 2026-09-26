"""Neo4j adapter for the attack graph (optional: ``pip install linchpin[neo4j]``).

Design (see docs/adr/0002-neo4j-adapter.md): the attack graph is *built* by the same code as
the in-memory store (so edge costs are identical and deterministic) and then **mirrored** into
Neo4j with idempotent ``MERGE`` batches, using exactly the frozen labels / relationship types
of contracts/graph_model.md. Neo4j is then the system of record for exploration (Browser,
Bloom, GDS); :meth:`Neo4jGraphStore.pull` reads a graph back into NetworkX so every engine
(paths, optimizer, cuts) runs unchanged on data that lives in Neo4j.

Without a server, :func:`to_cypher` renders the same statements as a ``.cypher`` script that
``cypher-shell -f`` can load.
"""
from __future__ import annotations

import json
from typing import Any, Iterable

import networkx as nx

from linchpin.config import Config
from linchpin.graph.store import GraphStore

LABELS = {"Host", "Service", "Vuln", "Credential", "Privilege", "DataStore", "Internet"}
BATCH = 500


def _props(d: dict[str, Any]) -> dict[str, Any]:
    """Neo4j properties must be primitives or homogeneous lists; everything else -> JSON."""
    out = {}
    for k, v in d.items():
        if k == "label" or v is None:
            continue
        if isinstance(v, (str, int, float, bool)):
            out[k] = v
        elif isinstance(v, list) and all(isinstance(x, (str, int, float, bool)) for x in v):
            out[k] = v
        else:
            out[k] = json.dumps(v, sort_keys=True, default=str)
    return out


def graph_rows(g: nx.DiGraph) -> tuple[dict[str, list[dict]], dict[str, list[dict]]]:
    nodes: dict[str, list[dict]] = {}
    for n, a in g.nodes(data=True):
        lbl = a.get("label", "Node")
        if lbl not in LABELS:
            raise ValueError(f"unexpected label {lbl!r} on {n}")
        nodes.setdefault(lbl, []).append({"id": n, "props": _props(a)})
    rels: dict[str, list[dict]] = {}
    for u, v, a in g.edges(data=True):
        props = {k: x for k, x in _props(a).items() if k != "rel"}  # rel is the relationship type
        rels.setdefault(a["rel"], []).append({"src": u, "dst": v, "props": props})
    return nodes, rels


def statements(g: nx.DiGraph, graph_name: str = "default") -> list[tuple[str, dict]]:
    """Parameterised, idempotent Cypher statements that mirror `g` into Neo4j."""
    nodes, rels = graph_rows(g)
    out: list[tuple[str, dict]] = [
        ("MATCH (n:LinchpinNode {graph: $graph}) DETACH DELETE n", {"graph": graph_name}),
    ]
    for lbl in sorted(nodes):
        out.append((f"CREATE CONSTRAINT linchpin_{lbl.lower()}_id IF NOT EXISTS "
                    f"FOR (n:{lbl}) REQUIRE (n.graph, n.id) IS UNIQUE", {}))
    for lbl, rows in sorted(nodes.items()):
        for i in range(0, len(rows), BATCH):
            out.append((f"UNWIND $rows AS r MERGE (n:{lbl}:LinchpinNode {{graph: $graph, id: r.id}}) "
                        "SET n += r.props", {"rows": rows[i:i + BATCH], "graph": graph_name}))
    for rel, rows in sorted(rels.items()):
        for i in range(0, len(rows), BATCH):
            out.append(("UNWIND $rows AS r "
                        "MATCH (a:LinchpinNode {graph: $graph, id: r.src}) "
                        "MATCH (b:LinchpinNode {graph: $graph, id: r.dst}) "
                        f"MERGE (a)-[e:{rel}]->(b) SET e += r.props",
                        {"rows": rows[i:i + BATCH], "graph": graph_name}))
    return out


def _lit(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, list):
        return "[" + ", ".join(_lit(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join(f"`{k}`: {_lit(x)}" for k, x in v.items()) + "}"
    return json.dumps(str(v))


def to_cypher(g: nx.DiGraph, graph_name: str = "default") -> str:
    """Render the mirror statements as a standalone script (parameters inlined)."""
    lines = []
    for q, params in statements(g, graph_name):
        body = q
        for k, v in params.items():
            body = body.replace(f"${k}", _lit(v))
        lines.append(body + ";")
    return "\n".join(lines) + "\n"


class Neo4jGraphStore(GraphStore):
    """GraphStore whose built graph is mirrored to (and can be re-read from) Neo4j."""

    def __init__(self, cfg: Config | None = None, driver=None, graph_name: str = "default",
                 database: str | None = None):
        super().__init__(cfg)
        self.graph_name = graph_name
        self.database = database
        self._driver = driver

    @classmethod
    def connect(cls, cfg: Config, password: str, graph_name: str = "default", **kw) -> "Neo4jGraphStore":
        from neo4j import GraphDatabase  # optional dependency
        drv = GraphDatabase.driver(cfg.neo4j.get("uri", "bolt://localhost:7687"),
                                   auth=(cfg.neo4j.get("user", "neo4j"), password))
        return cls(cfg, driver=drv, graph_name=graph_name, **kw)

    def _run(self, stmts: Iterable[tuple[str, dict]]) -> int:
        n = 0
        with self._driver.session(database=self.database) as s:
            for q, p in stmts:
                s.run(q, **p)
                n += 1
        return n

    def build_attack_graph(self):
        stats = super().build_attack_graph()
        if self._driver is not None:
            self.push()
        return stats

    def push(self) -> int:
        """Mirror the current in-memory attack graph into Neo4j. Returns statements executed."""
        return self._run(statements(self.g, self.graph_name))

    def pull(self) -> nx.DiGraph:
        """Replace the in-memory graph with the one stored in Neo4j (for engines to run on)."""
        g = nx.DiGraph()
        with self._driver.session(database=self.database) as s:
            for rec in s.run("MATCH (n:LinchpinNode {graph: $graph}) RETURN n.id AS id, labels(n) AS labels, "
                             "properties(n) AS props", graph=self.graph_name):
                lbl = next(x for x in rec["labels"] if x != "LinchpinNode")
                props = {k: v for k, v in dict(rec["props"]).items() if k not in ("graph", "id")}
                g.add_node(rec["id"], label=lbl, **props)
            for rec in s.run("MATCH (a:LinchpinNode {graph: $graph})-[e]->(b:LinchpinNode {graph: $graph}) "
                             "RETURN a.id AS src, b.id AS dst, type(e) AS rel, properties(e) AS props",
                             graph=self.graph_name):
                g.add_edge(rec["src"], rec["dst"], rel=rec["rel"], **dict(rec["props"]))
        self.g = g
        return g

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
