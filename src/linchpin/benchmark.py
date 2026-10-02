"""Remediation-ordering benchmark.

For each topology, every strategy proposes an ordered list of remediations; we apply its top
``budget`` fixes and measure what an attacker still has:

* ``disconnected`` -- no crown jewel reachable from any entrypoint any more
* ``residual``     -- number of distinct attack paths still enumerated (capped at ``k``)
* ``min_cost``     -- cheapest remaining attack path cost (inf when disconnected)

Strategies (:data:`STRATEGIES`):

* ``linchpin`` -- exact minimum vertex cut when it fits the budget, else greedy path set
  cover (this project); ``greedy`` -- the set cover alone.
* ``milp_interdiction`` / ``greedy_interdiction`` -- published shortest-path interdiction
  planners (:mod:`linchpin.engine.interdiction`): the exact budgeted MILP of Israeli & Wood
  (2002) and a Guo et al.-style greedy. They maximise the attacker's cheapest-path cost.
* ``cvss`` / ``epss`` / ``kev_epss`` -- score-sorted patch queues over all vulns (highest CVSS;
  highest EPSS; CISA KEV first, then EPSS -- BOD 22-01 style).
* ``*_reach`` -- the same queues restricted to vulns that lie on some entry -> crown-jewel
  route. They ignore the planted unreachable decoys and non-code-execution noise, so they are
  the like-for-like test of whether *path structure* (not just reachability) matters.
* ``betweenness`` (graph-aware, path-agnostic) and ``random``.

The exact min cut (engine/cuts.py) gives the true minimum number of fixes that disconnect
everything, and the interdiction MILP the best achievable cheapest-path cost, so optimality
gaps are reported too. Topology sizes: :func:`hosts_for_seed`.
"""
from __future__ import annotations

import math
import random
import statistics
import time

import networkx as nx

from linchpin.engine.cuts import chokepoints, min_remediation_cut
from linchpin.engine.interdiction import _relevant, exact_interdiction, greedy_interdiction
from linchpin.engine.optimizer import candidates, recommend
from linchpin.graph.store import GraphStore
from linchpin.synth.generator import generate
from linchpin.synth.topologies import generate_family

STRATEGIES = ("linchpin", "greedy", "milp_interdiction", "greedy_interdiction", "cvss", "cvss_reach",
              "epss", "epss_reach", "kev_epss", "kev_epss_reach", "betweenness", "random")
LABEL = {
    "linchpin": "LINCHPIN (exact cut, else greedy)", "greedy": "LINCHPIN greedy set cover only",
    "milp_interdiction": "Exact interdiction MILP (Israeli & Wood 2002)",
    "greedy_interdiction": "Greedy interdiction (Guo et al.-style)",
    "cvss": "CVSS-first", "cvss_reach": "CVSS-first, on-path vulns only",
    "epss": "EPSS-first", "epss_reach": "EPSS-first, on-path vulns only",
    "kev_epss": "KEV then EPSS", "kev_epss_reach": "KEV then EPSS, on-path vulns only",
    "betweenness": "Betweenness", "random": "Random",
}
MIN_N_FOR_CI = 10  # cost-gain intervals over fewer still-connected seeds are not reported


def hosts_for_seed(seed: int) -> int:
    """Topology size for a seed: 12..60 hosts, every size once per 49 seeds."""
    return 12 + seed % 49


def _vulns(store: GraphStore, on_path_only: bool = False) -> list[tuple[str, dict]]:
    keep = _relevant(store)[0] if on_path_only else None
    return [(n, a) for n, a in store.g.nodes(data=True)
            if a.get("label") == "Vuln" and (keep is None or n in keep)]


def cvss_baseline(store: GraphStore, budget: int, on_path_only: bool = False) -> list[str]:
    """Highest CVSS base score first (ties: node id)."""
    vulns = [(a.get("cvss_base") or 0.0, n) for n, a in _vulns(store, on_path_only)]
    return [n for _, n in sorted(vulns, key=lambda t: (-t[0], t[1]))[:budget]]


def order(store: GraphStore, strategy: str, budget: int, k: int = 100, seed: int = 0) -> list[str]:
    """The first ``budget`` remediation targets (node ids) proposed by ``strategy``."""
    on_path = strategy.endswith("_reach")
    base = strategy.removesuffix("_reach")
    if strategy == "linchpin":
        return [r.target_node for r in recommend(store, budget=budget, k=k)]
    if strategy == "greedy":
        return [r.target_node for r in recommend(store, budget=budget, k=k, exact=False)]
    if strategy == "milp_interdiction":
        return exact_interdiction(store, budget)["removed"]
    if strategy == "greedy_interdiction":
        return greedy_interdiction(store, budget)
    if base == "cvss":
        return cvss_baseline(store, budget, on_path)
    if base == "epss":
        v = sorted(_vulns(store, on_path), key=lambda t: (-(t[1].get("epss") or 0.0), t[0]))
        return [n for n, _ in v[:budget]]
    if base == "kev_epss":
        v = sorted(_vulns(store, on_path), key=lambda t: (not t[1].get("kev"), -(t[1].get("epss") or 0.0),
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
    """What an attacker still has after ``removed``: disconnection, residual paths, cheapest cost."""
    paths = store.k_shortest_paths(k=k, exclude=removed)
    return {"disconnected": not store.reachable_crown_jewels(exclude=removed), "residual": len(paths),
            "min_cost": paths[0].total_cost if paths else math.inf}


def fixes_to_disconnect(store: GraphStore, k: int, cap: int = 25) -> int | None:
    """Fixes the greedy set cover needs to disconnect every crown jewel (None: not within ``cap``)."""
    recs = recommend(store, budget=cap, k=k, exact=False)
    removed = [r.target_node for r in recs]
    return len(removed) if not store.reachable_crown_jewels(exclude=removed) else None


def run_one(family: str, seed: int, n_hosts: int, budget: int, k: int = 100,
            strategies: tuple[str, ...] = STRATEGIES) -> dict:
    """Build one seeded topology, run every strategy, and return one result row."""
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
    for s in strategies:
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
    row["top1_is_planted"] = bool(gt.linchpin) and row.get("linchpin_top1") == gt.linchpin
    row["top1_is_chokepoint"] = row.get("linchpin_top1") in set(chokepoints(store))
    row["cve_pool"] = gt.cve_pool
    row["total_ms"] = (time.perf_counter() - t0) * 1000
    return row


def wilson_ci(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a binomial proportion k/n."""
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    den = 1 + z * z / n
    mid = (p + z * z / (2 * n)) / den
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / den
    return (round(max(0.0, mid - half), 4), round(min(1.0, mid + half), 4))


def bootstrap_ci(xs: list[float], reps: int = 2000, seed: int = 0) -> tuple[float, float] | None:
    """Percentile-bootstrap 95% CI of the mean (seeded)."""
    if not xs:
        return None
    rng = random.Random(seed)
    n = len(xs)
    ms = sorted(sum(rng.choice(xs) for _ in range(n)) / n for _ in range(reps))
    return (round(ms[int(0.025 * reps)], 4), round(ms[int(0.975 * reps) - 1], 4))


def mcnemar_exact(b: int, c: int) -> float:
    """Two-sided exact McNemar p-value for discordant pair counts ``b`` and ``c``."""
    n = b + c
    if n == 0:
        return 1.0
    tail = sum(math.comb(n, i) for i in range(min(b, c) + 1)) / 2 ** n
    return min(1.0, 2 * tail)


def _paired(rs: list[dict], a: str, b: str) -> dict:
    """Disconnect outcomes of strategies ``a`` vs ``b`` on the same topologies (exact McNemar)."""
    only_a = sum(bool(r[f"{a}_disc"]) and not r[f"{b}_disc"] for r in rs)
    only_b = sum(bool(r[f"{b}_disc"]) and not r[f"{a}_disc"] for r in rs)
    return {"only_" + a: only_a, "only_" + b: only_b, "p_mcnemar": mcnemar_exact(only_a, only_b)}


def summarise(rows: list[dict], strategies: tuple[str, ...] = STRATEGIES) -> dict:
    """Per-family aggregates, Wilson CIs for rates, bootstrap CIs for gains, paired tests."""
    out: dict = {}
    fams = sorted({r["family"] for r in rows})
    for fam in fams:
        rs = [r for r in rows if r["family"] == fam]
        n = len(rs)
        agg: dict = {"n": n, "mean_nodes": statistics.mean(r["nodes"] for r in rs),
                     "nodes_range": [min(r["nodes"] for r in rs), max(r["nodes"] for r in rs)],
                     "hosts_range": [min(r["n_hosts"] for r in rs), max(r["n_hosts"] for r in rs)],
                     "with_chokepoint": sum(r["chokepoints"] > 0 for r in rs) / n}
        cuts = [r["min_cut"] for r in rs if r["min_cut"] is not None]
        agg["mean_min_cut"] = statistics.mean(cuts) if cuts else None
        opt_gain = {r["seed"]: r.get("milp_interdiction_gain") for r in rs}
        for s in strategies:
            resid = [r[f"{s}_resid"] / max(r["baseline_residual"], 1) for r in rs]
            k_disc = sum(bool(r[f"{s}_disc"]) for r in rs)
            gains = [r[f"{s}_gain"] for r in rs if math.isfinite(r[f"{s}_gain"])]
            share = [r[f"{s}_gain"] / opt_gain[r["seed"]] for r in rs
                     if opt_gain.get(r["seed"]) is not None and math.isfinite(opt_gain[r["seed"]])
                     and opt_gain[r["seed"]] > 0 and math.isfinite(r[f"{s}_gain"])]
            agg[s] = {
                "disconnect_rate": k_disc / n,
                "disconnect_ci95": wilson_ci(k_disc, n),
                "residual_frac": statistics.mean(resid),
                "residual_frac_se": statistics.pstdev(resid) / math.sqrt(n),
                "mean_ms": statistics.mean(r[f"{s}_ms"] for r in rs),
                # attacker-effort gain on still-connected topologies (edge-cost units), with its n
                "cost_gain_connected": statistics.mean(gains) if gains else None,
                "cost_gain_n": len(gains),
                "cost_gain_ci95": bootstrap_ci(gains) if len(gains) >= MIN_N_FOR_CI else None,
                # share of the best achievable cheapest-path cost gain (where nothing disconnects)
                "share_of_optimal_gain": statistics.mean(share) if share else None,
                "share_of_optimal_gain_n": len(share),
                "share_of_optimal_gain_ci95": bootstrap_ci(share) if len(share) >= MIN_N_FOR_CI else None,
            }
            if s != "linchpin" and "linchpin" in strategies:
                agg[s]["vs_linchpin"] = _paired(rs, "linchpin", s)
        opt = [(r["greedy_fixes"], r["min_cut"]) for r in rs if r["greedy_fixes"] and r["min_cut"]]
        agg["greedy_optimal_rate"] = (sum(g == m for g, m in opt) / len(opt)) if opt else None
        agg["greedy_mean_ratio"] = statistics.mean(g / m for g, m in opt) if opt else None
        agg["top1_chokepoint_rate"] = (sum(r["top1_is_chokepoint"] for r in rs if r["chokepoints"])
                                       / max(1, sum(1 for r in rs if r["chokepoints"])))
        planted = [r for r in rs if r["family"] in ("single", "legacy")]
        if planted:
            agg["top1_planted_rate"] = sum(r["top1_is_planted"] for r in planted) / len(planted)
        out[fam] = agg
    pool = [r for r in rows if r["family"] != "none"]
    if pool and "linchpin" in strategies:
        pooled_fams = sorted({r["family"] for r in pool})
        out["pooled"] = {"families": pooled_fams, "n": len(pool)}
        for s in strategies:
            k_disc = sum(bool(r[f"{s}_disc"]) for r in pool)
            out["pooled"][s] = {"disconnect_rate": k_disc / len(pool), "disconnect_ci95": wilson_ci(k_disc, len(pool))}
            if s != "linchpin":
                out["pooled"][s]["vs_linchpin"] = _paired(pool, "linchpin", s)
    if "cvss" in strategies and "linchpin" in strategies:
        red = [(r["cvss_resid"] - r["linchpin_resid"]) / max(r["baseline_residual"], 1) for r in rows]
        out["residual_reduction_vs_cvss"] = {"families": fams, "n": len(red), "mean": statistics.mean(red),
                                             "ci95": bootstrap_ci(red)}
    return out


def run(n_topologies: int = 100, budget: int = 2, k: int = 100) -> dict:
    """Legacy entry point (single planted linchpin, placeholder CVEs)."""
    strategies = ("linchpin", "cvss")
    rows = [run_one("legacy", s, 10 + (s % 30), budget, k, strategies) for s in range(n_topologies)]
    red = [(r["cvss_resid"] - r["linchpin_resid"]) / max(r["baseline_residual"], 1) for r in rows]
    return {
        "topologies": n_topologies, "budget": budget, "k_cap": k,
        "top1_accuracy": sum(r["top1_is_planted"] for r in rows) / n_topologies,
        "mean_residual_linchpin": statistics.mean(r["linchpin_resid"] for r in rows),
        "mean_residual_cvss": statistics.mean(r["cvss_resid"] for r in rows),
        "mean_reduction_vs_cvss": statistics.mean(red),
        "stdev_reduction_vs_cvss": statistics.pstdev(red),
    }
