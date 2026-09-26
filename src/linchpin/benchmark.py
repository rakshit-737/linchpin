"""Remediation-ordering benchmark.

For each topology, every strategy proposes an ordered list of remediations; we apply its top
``budget`` fixes and measure what an attacker still has:

* ``disconnected`` -- no crown jewel reachable from any entrypoint any more
* ``residual``     -- number of distinct attack paths still enumerated (capped at ``k``)
* ``min_cost``     -- cheapest remaining attack path cost (inf when disconnected)

Strategies: ``linchpin`` (greedy path set-cover, this project), ``cvss`` (highest CVSS base
first -- the classic patch queue), ``epss`` (highest EPSS first), ``kev_epss`` (CISA KEV
first, then EPSS -- BOD 22-01 style), ``betweenness`` (graph-aware but path-agnostic:
highest betweenness remediable node first) and ``random``.

An exact oracle (vertex min-cut, engine/cuts.py) gives the true minimum number of fixes that
disconnect everything, so the greedy optimizer's optimality gap is reported too.
"""
from __future__ import annotations

import math
import random
import statistics
import time

import networkx as nx

from linchpin.engine.cuts import chokepoints, min_remediation_cut
from linchpin.engine.optimizer import candidates, recommend
from linchpin.graph.store import GraphStore
from linchpin.synth.generator import generate
from linchpin.synth.topologies import generate_family

STRATEGIES = ("linchpin", "greedy", "cvss", "epss", "kev_epss", "betweenness", "random")


def _vulns(store):
    return [(n, a) for n, a in store.g.nodes(data=True) if a.get("label") == "Vuln"]


def cvss_baseline(store: GraphStore, budget: int) -> list[str]:
    vulns = [(a.get("cvss_base") or 0.0, n) for n, a in _vulns(store)]
    return [n for _, n in sorted(vulns, key=lambda t: (-t[0], t[1]))[:budget]]


def order(store: GraphStore, strategy: str, budget: int, k: int = 100, seed: int = 0) -> list[str]:
    if strategy == "linchpin":
        return [r.target_node for r in recommend(store, budget=budget, k=k)]
    if strategy == "greedy":
        return [r.target_node for r in recommend(store, budget=budget, k=k, exact=False)]
    if strategy == "cvss":
        return cvss_baseline(store, budget)
    if strategy == "epss":
        v = sorted(_vulns(store), key=lambda t: (-(t[1].get("epss") or 0.0), t[0]))
        return [n for n, _ in v[:budget]]
    if strategy == "kev_epss":
        v = sorted(_vulns(store), key=lambda t: (not t[1].get("kev"), -(t[1].get("epss") or 0.0),
                                                 -(t[1].get("cvss_base") or 0.0), t[0]))
        return [n for n, _ in v[:budget]]
    if strategy == "betweenness":
        cand = set(candidates(store))
        bc = nx.betweenness_centrality(store.g, weight="cost", seed=seed,
                                       k=min(200, store.g.number_of_nodes()))
        return [n for n, _ in sorted(((n, bc[n]) for n in cand), key=lambda t: (-t[1], t[0]))[:budget]]
    if strategy == "random":
        cand = candidates(store)
        return random.Random(seed).sample(cand, min(budget, len(cand)))
    raise ValueError(strategy)


def evaluate(store: GraphStore, removed: list[str], k: int) -> dict:
    paths = store.k_shortest_paths(k=k, exclude=removed)
    return {"disconnected": not store.reachable_crown_jewels(exclude=removed), "residual": len(paths),
            "min_cost": paths[0].total_cost if paths else math.inf}


def fixes_to_disconnect(store: GraphStore, k: int, cap: int = 25) -> int | None:
    recs = recommend(store, budget=cap, k=k, exact=False)
    removed = [r.target_node for r in recs]
    return len(removed) if not store.reachable_crown_jewels(exclude=removed) else None


def run_one(family: str, seed: int, n_hosts: int, budget: int, k: int = 100) -> dict:
    if family == "legacy":
        findings, gt = generate(n_hosts, 5, seed)
    else:
        findings, gt = generate_family(family, n_hosts, seed)
    store = GraphStore()
    store.upsert_findings(findings)
    t0 = time.perf_counter()
    bs = store.build_attack_graph()
    base = evaluate(store, [], k)
    row = {"family": family, "seed": seed, "n_hosts": n_hosts, "nodes": bs.nodes, "edges": bs.edges,
           "baseline_residual": base["residual"], "baseline_min_cost": base["min_cost"]}
    mc = min_remediation_cut(store)
    row["min_cut"] = None if mc is None else len(mc)
    row["chokepoints"] = len(chokepoints(store))
    for s in STRATEGIES:
        ts = time.perf_counter()
        rem = order(store, s, budget, k=k, seed=seed)
        ms = (time.perf_counter() - ts) * 1000
        ev = evaluate(store, rem, k)
        gain = ev["min_cost"] - base["min_cost"] if math.isfinite(ev["min_cost"]) else math.inf
        row.update({f"{s}_disc": ev["disconnected"], f"{s}_resid": ev["residual"],
                    f"{s}_cost": ev["min_cost"], f"{s}_gain": gain, f"{s}_ms": ms})
        if s == "linchpin":
            row["linchpin_top1"] = rem[0] if rem else ""
    row["greedy_fixes"] = fixes_to_disconnect(store, k)
    row["top1_is_planted"] = bool(gt.linchpin) and row["linchpin_top1"] == gt.linchpin
    row["top1_is_chokepoint"] = row["linchpin_top1"] in set(chokepoints(store))
    row["total_ms"] = (time.perf_counter() - t0) * 1000
    return row


def summarise(rows: list[dict]) -> dict:
    """Per-family aggregates (means with standard error)."""
    out: dict = {}
    for fam in sorted({r["family"] for r in rows}):
        rs = [r for r in rows if r["family"] == fam]
        n = len(rs)
        agg: dict = {"n": n, "mean_nodes": statistics.mean(r["nodes"] for r in rs),
                     "with_chokepoint": sum(r["chokepoints"] > 0 for r in rs) / n}
        cuts = [r["min_cut"] for r in rs if r["min_cut"] is not None]
        agg["mean_min_cut"] = statistics.mean(cuts) if cuts else None
        for s in STRATEGIES:
            resid = [r[f"{s}_resid"] / max(r["baseline_residual"], 1) for r in rs]
            agg[s] = {
                "disconnect_rate": sum(r[f"{s}_disc"] for r in rs) / n,
                "residual_frac": statistics.mean(resid),
                "residual_frac_se": statistics.pstdev(resid) / math.sqrt(n),
                "mean_ms": statistics.mean(r[f"{s}_ms"] for r in rs),
                # attacker-effort gain on still-connected topologies (edge-cost units)
                "cost_gain_connected": statistics.mean(
                    [r[f"{s}_gain"] for r in rs if math.isfinite(r[f"{s}_gain"])] or [0.0]),
            }
        opt = [(r["greedy_fixes"], r["min_cut"]) for r in rs if r["greedy_fixes"] and r["min_cut"]]
        agg["greedy_optimal_rate"] = (sum(g == m for g, m in opt) / len(opt)) if opt else None
        agg["greedy_mean_ratio"] = statistics.mean(g / m for g, m in opt) if opt else None
        agg["top1_chokepoint_rate"] = (sum(r["top1_is_chokepoint"] for r in rs if r["chokepoints"])
                                       / max(1, sum(1 for r in rs if r["chokepoints"])))
        planted = [r for r in rs if r["family"] in ("single", "legacy")]
        if planted:
            agg["top1_planted_rate"] = sum(r["top1_is_planted"] for r in planted) / len(planted)
        out[fam] = agg
    return out


def run(n_topologies: int = 100, budget: int = 2, k: int = 100) -> dict:
    """Legacy entry point (single planted linchpin, synthetic CVEs)."""
    rows = [run_one("legacy", s, 10 + (s % 30), budget, k) for s in range(n_topologies)]
    red = [(r["cvss_resid"] - r["linchpin_resid"]) / max(r["baseline_residual"], 1) for r in rows]
    return {
        "topologies": n_topologies, "budget": budget, "k_cap": k,
        "top1_accuracy": sum(r["top1_is_planted"] for r in rows) / n_topologies,
        "mean_residual_linchpin": statistics.mean(r["linchpin_resid"] for r in rows),
        "mean_residual_cvss": statistics.mean(r["cvss_resid"] for r in rows),
        "mean_reduction_vs_cvss": statistics.mean(red),
        "stdev_reduction_vs_cvss": statistics.pstdev(red),
    }
