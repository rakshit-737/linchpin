"""Neo4j adapter for the attack graph (optional: the ``[neo4j]`` extra, ``pip install ".[neo4j]"``).

Design (see docs/adr/0002-neo4j-adapter.md): the attack graph is *built* by the same code as
the in-memory store (so edge costs are identical and deterministic) and then **mirrored** into
Neo4j with idempotent ``MERGE`` batches, using exactly the frozen labels / relationship types
of contracts/graph_model.md. Neo4j is then the system of record for exploration (Browser,
Bloom, GDS); :meth:`Neo4jGraphStore.pull` reads a graph back into NetworkX so every engine
(paths, optimizer, cuts) runs unchanged on data that lives in Neo4j.

Without a server, :func:`to_cypher` renders the same statements as a ``.cypher`` script that
``cypher-shell -f`` can load.

With the Graph Data Science plugin installed, :meth:`Neo4jGraphStore.gds_k_shortest_paths`
runs Yen's k-shortest paths *inside* Neo4j (``gds.shortestPath.yens``) over the same ``cost``
property. CI cross-checks it against the in-memory engine (same path ids and costs) on
synthetic graphs with up to ~240k relationships and records both backends' timings.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterable
from typing import Any

import networkx as nx

from linchpin.config import Config
from linchpin.graph.store import GraphStore, path_from_nodes
from linchpin.models import AttackPath

LABELS = {"Host", "Service", "Vuln", "Credential", "Privilege", "DataStore", "Internet", "Ace"}
BATCH = 500

GDS_PROJECT = (
    "MATCH (s:LinchpinNode {graph: $graph}) "
    "OPTIONAL MATCH (s)-[r]->(t:LinchpinNode {graph: $graph}) "
    "WITH gds.graph.project($name, s, t, {relationshipProperties: r {.cost}}) AS g "
    "RETURN g.graphName AS name, g.nodeCount AS nodes, g.relationshipCount AS rels, "
    "g.projectMillis AS ms")
GDS_YENS = (
    "MATCH (a:LinchpinNode {graph: $graph, id: $src}), (b:LinchpinNode {graph: $graph, id: $dst}) "
    "CALL gds.shortestPath.yens.stream($name, {sourceNode: a, targetNode: b, k: $k, "
    "relationshipWeightProperty: 'cost'}) "
    "YIELD index, totalCost, nodeIds "
    "RETURN index, totalCost, [n IN gds.util.asNodes(nodeIds) | n.id] AS ids ORDER BY index")


def _props(d: dict[str, Any]) -> dict[str, Any]:
    """Neo4j properties must be primitives or homogeneous lists; everything else -> JSON."""
    out = {}
    for k, v in d.items():
        if k == "label" or v is None:
            continue
        prim = (str, int, float, bool)
        if isinstance(v, prim) or (isinstance(v, list) and all(isinstance(x, prim) for x in v)):
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
    # composite range index (works on Community Edition; uniqueness is enforced by MERGE)
    out.insert(0, ("CREATE INDEX linchpin_node_key IF NOT EXISTS FOR (n:LinchpinNode) ON (n.graph, n.id)", {}))
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


_PARAM = re.compile(r"\$([A-Za-z_][A-Za-z0-9_]*)\b")


def _lit(v: Any) -> str:
    """Cypher literal for a parameter value (strings JSON-quoted, map keys backtick-escaped)."""
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return repr(v)
    if isinstance(v, list):
        return "[" + ", ".join(_lit(x) for x in v) + "]"
    if isinstance(v, dict):
        return "{" + ", ".join(f"`{str(k).replace('`', '``')}`: {_lit(x)}" for k, x in v.items()) + "}"
    return json.dumps(str(v))


def to_cypher(g: nx.DiGraph, graph_name: str = "default") -> str:
    """Render the mirror statements as a standalone ``cypher-shell -f`` script (parameters inlined).

    Parameters are substituted in one pass over the *query template* only, so data that happens
    to contain ``$graph`` or ``$rows`` (e.g. a scanned service banner) is never re-substituted.
    """
    def inline(q: str, params: dict) -> str:
        return _PARAM.sub(lambda m: _lit(params[m.group(1)]) if m.group(1) in params else m.group(0), q)

    return "\n".join(inline(q, params) + ";" for q, params in statements(g, graph_name)) + "\n"


class Neo4jGraphStore(GraphStore):
    """GraphStore whose built graph is mirrored to (and can be re-read from) Neo4j."""

    def __init__(self, cfg: Config | None = None, driver=None, graph_name: str = "default",
                 database: str | None = None):
        super().__init__(cfg)
        self.graph_name = graph_name
        self.database = database
        self._driver = driver

    @classmethod
    def connect(cls, cfg: Config, password: str, graph_name: str = "default", **kw) -> Neo4jGraphStore:
        """Open a driver for ``cfg.neo4j`` and verify that the server answers and accepts the login.

        Raises:
            neo4j.exceptions.ServiceUnavailable: nothing answers at the configured URI.
            neo4j.exceptions.AuthError: the credentials are rejected.
        """
        from neo4j import GraphDatabase  # optional dependency
        drv = GraphDatabase.driver(cfg.neo4j.get("uri", "bolt://localhost:7687"),
                                   auth=(cfg.neo4j.get("user", "neo4j"), password))
        try:
            drv.verify_connectivity()
        except Exception:
            drv.close()
            raise
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

    # ------------------------------------------------------------ GDS backend
    def gds_version(self) -> str | None:
        """Installed Graph Data Science version, or None when the server reports ``gds.*`` unknown.

        Only "unknown function / procedure" errors mean the plugin is missing. Connection and
        authentication failures propagate, so a wrong URI or password is never reported as
        "GDS not installed".
        """
        from neo4j.exceptions import AuthError, ClientError
        try:
            with self._driver.session(database=self.database) as s:
                rec = s.run("RETURN gds.version() AS v").single()
                return None if rec is None else str(rec["v"])
        except AuthError:
            raise
        except ClientError as e:
            text = f"{getattr(e, 'code', '')} {getattr(e, 'message', '')} {e}".lower()
            if any(m in text for m in ("unknown function", "procedurenotfound", "no procedure")):
                return None
            raise

    def gds_project(self, name: str | None = None) -> dict:
        """(Re)create an in-memory GDS projection of this graph with ``cost`` on every relationship."""
        name = name or f"linchpin-{self.graph_name}"
        with self._driver.session(database=self.database) as s:
            s.run("CALL gds.graph.drop($name, false) YIELD graphName RETURN graphName", name=name).consume()
            rec = s.run(GDS_PROJECT, graph=self.graph_name, name=name).single()
        return {"name": rec["name"], "nodes": rec["nodes"], "relationships": rec["rels"], "project_ms": rec["ms"]}

    def gds_k_shortest_paths(self, sources: list[str] | None = None, targets: list[str] | None = None,
                             k: int | None = None, name: str | None = None) -> list[AttackPath]:
        """Yen's k-shortest paths computed by Neo4j GDS (same semantics as ``k_shortest_paths``).

        GDS Yen is single-source/single-target, so every (entrypoint, crown jewel) pair is solved
        and the union is cut to the k cheapest -- the global k shortest are among each pair's k
        shortest. Requires :meth:`gds_project` first; edge ids and kill-chain stages are filled in
        from the in-memory graph (call :meth:`pull` first when the graph only lives in Neo4j).
        """
        k = k or self.cfg.k_shortest
        name = name or f"linchpin-{self.graph_name}"
        sources = sources or self.entrypoints()
        targets = targets or self.crown_jewels()
        rows: list[tuple[float, list[str]]] = []
        with self._driver.session(database=self.database) as s:
            for src in sources:
                for dst in targets:
                    for rec in s.run(GDS_YENS, graph=self.graph_name, name=name, src=src, dst=dst, k=k):
                        rows.append((float(rec["totalCost"]), list(rec["ids"])))
        rows.sort(key=lambda t: (t[0], t[1]))
        return [path_from_nodes(self.g, nodes, cost) for cost, nodes in rows[:k]]

    def close(self) -> None:
        if self._driver is not None:
            self._driver.close()
