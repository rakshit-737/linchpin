"""Neo4j GDS backend: Yen's k-shortest paths computed inside Neo4j must match the in-memory
NetworkX engine exactly (same path ids, same costs).

* ``test_gds_yens_mapping_offline`` exercises the result mapping with a fake driver.
* ``test_gds_version_*`` check that only "unknown function" means "plugin missing".
* ``test_gds_large_graph_crosscheck`` (marker ``neo4j_gds``) loads synthetic graphs of
  increasing size into a live Neo4j with the GDS plugin, runs ``gds.shortestPath.yens`` and
  the NetworkX engine on each, compares them and records both timings in
  ``$LINCHPIN_ARTIFACT_DIR/gds_crosscheck.json``. ``LINCHPIN_GDS_SWEEP`` lists
  ``hosts:k`` pairs (default ``250:10``); ``LINCHPIN_GDS_REPEATS`` timed runs per backend
  (default 10; median and interquartile range). With a server configured, a missing plugin *fails*
  the test unless ``LINCHPIN_GDS_OPTIONAL=1``: a green CI job must mean the comparison ran.
"""
from __future__ import annotations

import json
import os
import platform
import statistics
import time
from pathlib import Path

import pytest

pytest.importorskip("neo4j")
from neo4j.exceptions import ClientError, ServiceUnavailable

from linchpin.graph.neo4j_store import GDS_YENS, Neo4jGraphStore
from linchpin.graph.store import GraphStore
from linchpin.runinfo import run_provenance
from linchpin.synth.topologies import generate_family


class _Result(list):
    def single(self):
        return self[0] if self else None

    def consume(self):
        return None


class _GdsSession:
    def __init__(self, paths, version_error=None):
        self.paths = paths  # {(src, dst): [(cost, [ids...]), ...]}
        self.version_error = version_error

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, q, **p):
        if q == GDS_YENS:
            rows = self.paths.get((p["src"], p["dst"]), [])[: p["k"]]
            return _Result({"index": i, "totalCost": c, "ids": ids} for i, (c, ids) in enumerate(rows))
        if "gds.version" in q:
            raise self.version_error or ClientError("Unknown function 'gds.version'")
        return _Result()


class _GdsDriver:
    def __init__(self, paths, version_error=None):
        self.paths = paths
        self.version_error = version_error

    def session(self, database=None):
        return _GdsSession(self.paths, self.version_error)

    def close(self):
        pass


def _built(family="single", n=20, seed=0, driver=None, graph_name="t") -> Neo4jGraphStore:
    f, _ = generate_family(family, n, seed)
    s = Neo4jGraphStore(driver=None, graph_name=graph_name)
    s.upsert_findings(f)
    GraphStore.build_attack_graph(s)  # in-memory build only (no push)
    s._driver = driver
    return s


def test_gds_yens_mapping_offline():
    ref = _built()
    want = ref.k_shortest_paths(k=5)
    assert want, "fixture must have attack paths"
    # feed the reference paths back as if GDS had computed them (shuffled per pair)
    paths: dict = {}
    for p in reversed(want):
        paths.setdefault((p.nodes[0], p.crown_jewel), []).append((p.total_cost, p.nodes))
    for v in paths.values():
        v.sort()
    s = _built(driver=_GdsDriver(paths))
    got = s.gds_k_shortest_paths(k=5)
    assert [p.total_cost for p in got] == sorted(p.total_cost for p in want)  # cheapest first
    by_id = {p.path_id: p for p in want}
    assert set(by_id) == {p.path_id for p in got}
    for p in got:  # edge ids and kill-chain stages are rebuilt identically from the graph
        assert (p.edges, p.stages, p.crown_jewel) == (by_id[p.path_id].edges, by_id[p.path_id].stages,
                                                      by_id[p.path_id].crown_jewel)


def test_gds_version_unknown_function_means_missing_plugin():
    assert _built(driver=_GdsDriver({})).gds_version() is None


def test_gds_version_does_not_hide_connection_failures():
    s = _built(driver=_GdsDriver({}, version_error=ServiceUnavailable("connection refused")))
    with pytest.raises(ServiceUnavailable):
        s.gds_version()


def test_connect_verifies_connectivity():
    from linchpin.config import Config
    with pytest.raises(ServiceUnavailable):
        Neo4jGraphStore.connect(Config(neo4j={"uri": "bolt://127.0.0.1:1"}), "wrong-pw")


def _quartiles(xs: list[float]) -> dict:
    q1, med, q3 = statistics.quantiles(xs, n=4, method="inclusive") if len(xs) > 1 else (xs[0],) * 3
    return {"median": round(med, 4), "q1": round(q1, 4), "q3": round(q3, 4)}


def _crosscheck(s: Neo4jGraphStore, hosts: int, k: int, repeats: int = 10) -> dict:
    f, gt = generate_family("single", hosts, 1)
    s.findings = {}
    s.upsert_findings(f)
    t0 = time.perf_counter()
    GraphStore.build_attack_graph(s)
    build_s = time.perf_counter() - t0
    t0 = time.perf_counter()
    s.push()
    push_s = time.perf_counter() - t0
    proj = s.gds_project()
    nx_times, gds_times = [], []
    for _ in range(repeats):  # timed runs per backend, interleaved
        t0 = time.perf_counter()
        nx_paths = s.k_shortest_paths(k=k)
        nx_times.append(time.perf_counter() - t0)
        t0 = time.perf_counter()
        gds_paths = s.gds_k_shortest_paths(k=k)
        gds_times.append(time.perf_counter() - t0)
    nx_costs = [p.total_cost for p in nx_paths]
    gds_costs = [p.total_cost for p in gds_paths]
    # paths strictly cheaper than the k-th cost are unique regardless of tie-breaking
    kth = nx_costs[-1] if nx_costs else 0.0
    nx_strict = sorted(p.path_id for p in nx_paths if p.total_cost < kth - 1e-9)
    gds_strict = sorted(p.path_id for p in gds_paths if p.total_cost < kth - 1e-9)
    return {
        "family": "single", "hosts": hosts, "k": k, "planted_linchpin": gt.linchpin,
        "graph": {"nodes": s.g.number_of_nodes(), "relationships": s.g.number_of_edges()},
        "projection": proj,
        "timings_s": {"build": round(build_s, 3), "push": round(push_s, 3), "repeats": repeats,
                      "networkx_yen_median": round(statistics.median(nx_times), 4),
                      "gds_yen_median": round(statistics.median(gds_times), 4),
                      "networkx_yen": _quartiles(nx_times), "gds_yen": _quartiles(gds_times),
                      "networkx_yen_runs": [round(x, 4) for x in nx_times],
                      "gds_yen_runs": [round(x, 4) for x in gds_times]},
        "speedup_median": round(statistics.median(nx_times) / statistics.median(gds_times), 2),
        "networkx_costs": nx_costs, "gds_costs": gds_costs,
        "strictly_cheaper_than_kth": {"networkx": nx_strict, "gds": gds_strict},
        "top_path_networkx": nx_paths[0].nodes if nx_paths else [],
        "top_path_gds": gds_paths[0].nodes if gds_paths else [],
    }


@pytest.mark.neo4j_gds
@pytest.mark.skipif(not (os.environ.get("NEO4J_URI") and os.environ.get("NEO4J_PASSWORD")),
                    reason="no Neo4j server configured")
def test_gds_large_graph_crosscheck():
    from linchpin.config import Config
    sweep = [tuple(int(x) for x in item.split(":"))
             for item in os.environ.get("LINCHPIN_GDS_SWEEP", "250:10").split(",") if item]
    cfg = Config(neo4j={"uri": os.environ["NEO4J_URI"], "user": os.environ.get("NEO4J_USER", "neo4j")})
    s = Neo4jGraphStore.connect(cfg, os.environ["NEO4J_PASSWORD"], graph_name="gds-ci")
    try:
        version = s.gds_version()
        if version is None:
            if os.environ.get("LINCHPIN_GDS_OPTIONAL") == "1":
                pytest.skip("Neo4j is up but the Graph Data Science plugin is not installed")
            pytest.fail("Neo4j is up but the Graph Data Science plugin is not installed")
        with s._driver.session() as sess:
            server = sess.run("CALL dbms.components() YIELD name, versions, edition "
                              "RETURN name, versions[0] AS version, edition").single()
        repeats = int(os.environ.get("LINCHPIN_GDS_REPEATS", "10"))
        runs = [_crosscheck(s, hosts, k, repeats) for hosts, k in sweep]
    finally:
        s.close()
    result = {"gds_version": version, "neo4j": dict(server) if server else None,
              "python": platform.python_version(), "machine": platform.machine(), "code": run_provenance(),
              "runs": runs}
    out = Path(os.environ.get("LINCHPIN_ARTIFACT_DIR", "artifacts"))
    out.mkdir(parents=True, exist_ok=True)
    (out / "gds_crosscheck.json").write_text(json.dumps(result, indent=2), encoding="utf-8")

    for r in runs:
        assert r["projection"]["nodes"] == r["graph"]["nodes"], r["hosts"]
        assert r["projection"]["relationships"] == r["graph"]["relationships"], r["hosts"]
        assert len(r["gds_costs"]) == len(r["networkx_costs"]) == r["k"], r["hosts"]
        assert r["gds_costs"] == pytest.approx(r["networkx_costs"], abs=1e-5), r["hosts"]
        assert r["strictly_cheaper_than_kth"]["gds"] == r["strictly_cheaper_than_kth"]["networkx"], r["hosts"]
        assert r["planted_linchpin"] in r["top_path_gds"]  # every path crosses the planted bastion
