"""Ranking-vs-CVSS experiment: residual crown-jewel paths after a fixed remediation budget."""
from __future__ import annotations

import statistics

from linchpin.engine.optimizer import recommend
from linchpin.graph.store import GraphStore
from linchpin.synth.generator import generate


def cvss_baseline(store: GraphStore, budget: int) -> list[str]:
    vulns = [(a.get("cvss_base") or 0.0, n) for n, a in store.g.nodes(data=True) if a.get("label") == "Vuln"]
    return [n for _, n in sorted(vulns, key=lambda t: (-t[0], t[1]))[:budget]]


def run_one(seed: int, n_hosts: int = 20, budget: int = 2, k: int = 100) -> dict:
    findings, gt = generate(n_hosts, 5, seed)
    store = GraphStore()
    store.upsert_findings(findings)
    store.build_attack_graph()
    lp = [r.target_node for r in recommend(store, budget=budget, k=k)]
    cv = cvss_baseline(store, budget)
    return {
        "seed": seed,
        "linchpin_top1_correct": bool(lp) and lp[0] == gt.linchpin,
        "residual_linchpin": len(store.k_shortest_paths(k=k, exclude=lp)),
        "residual_cvss": len(store.k_shortest_paths(k=k, exclude=cv)),
        "baseline_total": len(store.k_shortest_paths(k=k)),
    }


def run(n_topologies: int = 100, budget: int = 2, k: int = 100) -> dict:
    rows = [run_one(s, n_hosts=10 + (s % 30), budget=budget, k=k) for s in range(n_topologies)]
    red = [(r["residual_cvss"] - r["residual_linchpin"]) / max(r["baseline_total"], 1) for r in rows]
    return {
        "topologies": n_topologies, "budget": budget, "k_cap": k,
        "top1_accuracy": sum(r["linchpin_top1_correct"] for r in rows) / n_topologies,
        "mean_residual_linchpin": statistics.mean(r["residual_linchpin"] for r in rows),
        "mean_residual_cvss": statistics.mean(r["residual_cvss"] for r in rows),
        "mean_reduction_vs_cvss": statistics.mean(red),
        "stdev_reduction_vs_cvss": statistics.pstdev(red),
    }
