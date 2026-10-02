"""Ablation: which ingredient of LINCHPIN makes its remediation plans work?

The claim under test: *fusing* scanner, identity and segmentation data into one attack graph
and solving an exact minimum vertex cut finds plans that cut crown jewels off, where any
single data source or a score-sorted queue does not.

Every planner below runs the **same engine** (``optimizer.recommend``) on a *degraded view*
of the findings, and every plan is then scored on the **full ground-truth graph** -- what
happens when a tool plans from incomplete data and the attacker uses the real network:

* ``fused``             -- all findings (LINCHPIN as shipped). It plans on the graph it is
                           scored on, so it disconnects by construction whenever the exact
                           min cut fits the budget; the evidence is in the other rows.
* ``no_exact_cut``      -- all findings, greedy set cover only (no max-flow cut)
* ``no_identity``       -- credential / ACL findings removed (scanner + firewall view, the view
                           of a vulnerability-management tool)
* ``drop_identity_NN``  -- a seeded NN% of the credential / ACL findings removed (dose-response)
* ``no_segmentation``   -- reachability rules removed and every host put in one flat segment
                           (what a planner must assume without firewall data)
* ``no_vuln_semantics`` -- every CVE treated as code execution (no CVSS-vector impact gating)
* ``uniform_cost``      -- every exploit equally hard (exploitability 0.5, no CVSS / EPSS / KEV):
                           isolates the intel-based edge costs; also reports how far its path
                           ranking moves from the real one (Kendall tau, top-10 overlap)
* ``identity_only``     -- CVE findings removed, internet-facing hosts assumed owned (the view
                           of an identity-graph tool such as BloodHound)
* ``kev_epss_queue``    -- no graph at all: patch KEV first, then by EPSS (BOD 22-01 style)

    python benchmarks/ablation.py --seeds 50 --budget 3 --workers 8

Writes benchmarks/results/ablation.{json,md} and ablation_rows.csv.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import random
import statistics
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from linchpin.benchmark import bootstrap_ci, evaluate, hosts_for_seed, mcnemar_exact, order, wilson_ci
from linchpin.config import Config
from linchpin.engine.optimizer import recommend
from linchpin.graph.store import GraphStore
from linchpin.models import NormalizedFinding
from linchpin.synth.topologies import FAMILIES, generate_family, pool_provenance

DOSES = (10, 25, 50)
VIEWS = ("fused", "no_exact_cut", "no_identity", *(f"drop_identity_{d}" for d in DOSES), "no_segmentation",
         "no_vuln_semantics", "uniform_cost", "identity_only", "kev_epss_queue")
LABEL = {
    "fused": "LINCHPIN (fused data, exact cut)",
    "no_exact_cut": "- exact cut (greedy only)",
    "no_identity": "- identity data (scanner + firewall view)",
    **{f"drop_identity_{d}": f"- {d}% of identity findings" for d in DOSES},
    "no_segmentation": "- segmentation data (flat network assumed)",
    "no_vuln_semantics": "- exploit semantics (every CVE = RCE)",
    "uniform_cost": "- exploit intel (uniform edge costs)",
    "identity_only": "identity data only (BloodHound-style view)",
    "kev_epss_queue": "no graph: KEV then EPSS queue",
}
LONG_BUDGET = 12


def _flat(f: NormalizedFinding) -> NormalizedFinding | None:
    if f.kind == "reachability":
        return None
    d = dict(f.detail or {})
    if f.kind == "config" and d.get("issue") == "inventory":
        d["segment"] = "flat"
        return f.model_copy(update={"detail": d})
    return f


def _all_rce(f: NormalizedFinding) -> NormalizedFinding:
    if f.kind != "cve":
        return f
    d = dict(f.detail or {})
    d["impact_class"] = None
    return f.model_copy(update={"detail": d})


def _uniform(f: NormalizedFinding) -> NormalizedFinding:
    if f.kind != "cve":
        return f
    d = {k: v for k, v in (f.detail or {}).items() if k not in ("cvss_exploitability", "kev")}
    return f.model_copy(update={"cvss_base": None, "epss": None, "detail": d})


def view(findings: list[NormalizedFinding], name: str, seed: int = 0) -> tuple[list[NormalizedFinding], Config]:
    """Degraded finding set (and config) the planner sees under ablation ``name``."""
    cfg = Config()
    if name == "no_identity":
        return [f for f in findings if f.kind not in ("credential", "acl")], cfg
    if name.startswith("drop_identity_"):
        pct = int(name.rsplit("_", 1)[1])
        ident = sorted(f.finding_id for f in findings if f.kind in ("credential", "acl"))
        drop = set(random.Random(seed * 7919 + pct).sample(ident, round(len(ident) * pct / 100)))
        return [f for f in findings if f.finding_id not in drop], cfg
    if name == "no_segmentation":
        return [g for f in findings if (g := _flat(f)) is not None], cfg
    if name == "no_vuln_semantics":
        return [_all_rce(f) for f in findings], cfg
    if name == "uniform_cost":
        return [_uniform(f) for f in findings], cfg
    if name == "identity_only":
        keep = [f for f in findings if f.kind != "cve"]
        facing = sorted({f.host_id for f in keep if f.kind == "config"
                         and (f.detail or {}).get("internet_facing")})
        return keep, cfg.model_copy(update={"entrypoints": facing or ["auto:internet_facing"]})
    return findings, cfg


def _view_store(findings: list[NormalizedFinding], name: str, seed: int) -> GraphStore:
    fs, cfg = view(findings, name, seed)
    s = GraphStore(cfg)
    s.upsert_findings(fs)
    s.build_attack_graph()
    return s


def plan(vs: GraphStore | None, truth: GraphStore, name: str, budget: int, k: int) -> list[str]:
    """Ordered fixes proposed by planner ``name`` (computed on its view ``vs``), as truth node ids."""
    if name == "kev_epss_queue":
        rem = order(truth, "kev_epss", budget, k=k)
    else:
        rem = [r.target_node for r in recommend(vs, budget=budget, k=k, exact=name != "no_exact_cut")]
    return [n for n in rem if n in truth.g]


def fixes_needed(truth: GraphStore, rem: list[str]) -> int | None:
    """Shortest prefix of the plan that cuts every crown jewel off in the real graph (None: never)."""
    for i in range(1, len(rem) + 1):
        if not truth.reachable_crown_jewels(exclude=rem[:i]):
            return i
    return None


def _kendall_tau(a: list[float], b: list[float]) -> float | None:
    if len(a) < 3:
        return None
    from scipy.stats import kendalltau
    tau = kendalltau(a, b).statistic
    return None if tau is None or math.isnan(tau) else round(float(tau), 4)


def ranking_shift(truth: GraphStore, vs: GraphStore, k: int = 100) -> dict:
    """How the uniform-cost view re-ranks the real top-k attack paths."""
    real = truth.k_shortest_paths(k=k)
    own = vs.k_shortest_paths(k=10)
    re_costed = [sum(vs.g.edges[u, v]["cost"] for u, v in zip(p.nodes, p.nodes[1:], strict=False)) for p in real]
    top_real = {p.path_id for p in real[:10]}
    return {"kendall_tau": _kendall_tau([p.total_cost for p in real], re_costed),
            "top10_overlap": len(top_real & {p.path_id for p in own}) / max(1, min(10, len(top_real)))}


def run_one(family: str, seed: int, n_hosts: int, budget: int, k: int) -> dict:
    from linchpin.engine.cuts import min_remediation_cut
    findings, _ = generate_family(family, n_hosts, seed)
    truth = GraphStore()
    truth.upsert_findings(findings)
    truth.build_attack_graph()
    base = evaluate(truth, [], k)
    opt = min_remediation_cut(truth)
    row: dict = {"family": family, "seed": seed, "n_hosts": n_hosts, "nodes": truth.g.number_of_nodes(),
                 "baseline_residual": base["residual"], "baseline_min_cost": base["min_cost"],
                 "optimum": None if opt is None else len(opt)}
    for name in VIEWS:
        t0 = time.perf_counter()
        vs = None if name == "kev_epss_queue" else _view_store(findings, name, seed)
        rem = plan(vs, truth, name, budget, k)
        ev = evaluate(truth, rem, k)
        row[f"{name}_disc"] = ev["disconnected"]
        row[f"{name}_resid"] = ev["residual"] / max(base["residual"], 1)
        row[f"{name}_gain"] = (ev["min_cost"] - base["min_cost"]) if math.isfinite(ev["min_cost"]) else math.inf
        # same planner with a generous budget: how many of its fixes does the real graph need?
        row[f"{name}_needed"] = fixes_needed(truth, plan(vs, truth, name, LONG_BUDGET, k))
        if name == "uniform_cost":
            row.update({f"uniform_{key}": v for key, v in ranking_shift(truth, vs).items()})
        row[f"{name}_ms"] = round((time.perf_counter() - t0) * 1000, 1)
    return row


def _excess(rs: list[dict], name: str) -> dict:
    """Fixes the planner needs on the real graph, relative to the exact optimum (mean, bootstrap CI)."""
    with_opt = [r for r in rs if r["optimum"]]
    ratios = [r[f"{name}_needed"] / r["optimum"] for r in with_opt if r[f"{name}_needed"] is not None]
    never = sum(r[f"{name}_needed"] is None for r in with_opt)
    return {"needed_over_optimum": round(statistics.mean(ratios), 3) if ratios else None,
            "needed_over_optimum_ci95": bootstrap_ci(ratios) if len(ratios) >= 10 else None,
            "needed_n": len(ratios),
            "optimal_rate": round(sum(x == 1 for x in ratios) / len(ratios), 4) if ratios else None,
            "never_rate": round(never / max(1, len(with_opt)), 4)}


def _disc(rs: list[dict], name: str) -> dict:
    kd = sum(bool(r[f"{name}_disc"]) for r in rs)
    out = {"disconnect_rate": round(kd / len(rs), 4), "disconnect_ci95": wilson_ci(kd, len(rs))}
    if name != "fused":
        only_f = sum(bool(r["fused_disc"]) and not r[f"{name}_disc"] for r in rs)
        only_v = sum(bool(r[f"{name}_disc"]) and not r["fused_disc"] for r in rs)
        out["vs_fused"] = {"only_fused": only_f, "only_view": only_v, "p_mcnemar": mcnemar_exact(only_f, only_v)}
    return out


def summarise(rows: list[dict]) -> dict:
    out: dict = {}
    for fam in sorted({r["family"] for r in rows}):
        rs = [r for r in rows if r["family"] == fam]
        opts = [r["optimum"] for r in rs if r["optimum"] is not None]
        agg: dict = {"n": len(rs), "mean_optimum": round(statistics.mean(opts), 3) if opts else None}
        for name in VIEWS:
            gains = [r[f"{name}_gain"] for r in rs if math.isfinite(r[f"{name}_gain"])]
            agg[name] = {**_disc(rs, name),
                         "residual_frac": round(statistics.mean(r[f"{name}_resid"] for r in rs), 4),
                         "cost_gain": round(statistics.mean(gains), 4) if gains else None,
                         "cost_gain_n": len(gains),
                         "cost_gain_ci95": bootstrap_ci(gains) if len(gains) >= 10 else None,
                         **_excess(rs, name)}
        taus = [r["uniform_kendall_tau"] for r in rs if r.get("uniform_kendall_tau") is not None]
        ovl = [r["uniform_top10_overlap"] for r in rs if r.get("uniform_top10_overlap") is not None]
        agg["uniform_cost_ranking"] = {
            "kendall_tau": round(statistics.mean(taus), 3) if taus else None,
            "kendall_tau_ci95": bootstrap_ci(taus) if len(taus) >= 10 else None,
            "top10_overlap": round(statistics.mean(ovl), 3) if ovl else None,
            "top10_overlap_ci95": bootstrap_ci(ovl) if len(ovl) >= 10 else None}
        out[fam] = agg
    pool = [r for r in rows if r["family"] != "none"]  # where a small plan can disconnect at all
    if pool:
        out["pooled"] = {"families": sorted({r["family"] for r in pool}), "n": len(pool),
                         **{name: _disc(pool, name) for name in VIEWS}}
    return out


def _cell(a: dict) -> str:
    lo, hi = a["disconnect_ci95"]
    txt = f"{a['disconnect_rate']:.0%} [{lo:.0%}, {hi:.0%}]"
    vs = a.get("vs_fused")
    if vs and vs["only_fused"] + vs["only_view"]:
        p = vs["p_mcnemar"]
        txt += f", p={'<1e-4' if p < 1e-4 else format(p, '.2g')}"
    return txt


def md(summ: dict, budget: int, seeds: int) -> str:
    fams = [f for f in summ if f != "pooled"]
    pooled = summ.get("pooled")
    cols = [*fams, *(["pooled"] if pooled else [])]
    pooled_label = f"pooled ({'+'.join(pooled['families'])}, n={pooled['n']})" if pooled else ""
    head = "| planner (view of the data) | " + " | ".join(fams) + (f" | {pooled_label} |" if pooled else " |")
    lines = [
        (f"Budget {budget} fixes, {seeds} seeds per family. Each planner runs the same optimiser on a degraded "
         "view of the findings; its plan is scored on the **full** ground-truth graph. Cells: share of topologies "
         "where the crown jewel is cut off, 95% Wilson interval, and the exact McNemar p-value of the paired "
         "difference to the fused planner (omitted when the two never differ). The fused planner plans on the very "
         "graph it is scored on, so its 100% is guaranteed whenever the exact min cut fits the budget (max-flow / "
         "min-cut); the evidence is how far each degraded view falls short of it."),
        "",
        head,
        "| --- |" + " ---: |" * len(cols),
    ]
    for name in VIEWS:
        cells = [_cell(summ[f][name]) for f in cols]
        lab = f"**{LABEL[name]}**" if name == "fused" else LABEL[name]
        lines.append(f"| {lab} | " + " | ".join(cells) + " |")
    if "none" in summ:
        lines += ["", ("`none` has a mean exact min cut of about 7 fixes, so no 3-fix plan can disconnect it; it is "
                       "excluded from the pooled column, and its rows are compared by attacker cost gain below.")]
    lines += ["", "### Fixes needed on the real graph", "",
              (f"Each planner again with a generous budget ({LONG_BUDGET}): how many of its fixes, taken in its own "
               "order, the *real* graph needs before every crown jewel is cut off, as a multiple of the exact minimum "
               "cut (1.00 = optimal; mean with 95% bootstrap interval). \"never\" = share of topologies its plan does "
               "not disconnect at all. Views that over-approximate the network (flat, every CVE = RCE) always "
               "disconnect it eventually, because a cut of a super-graph also cuts the real graph; their cost is "
               "extra fixes."), "",
              "| planner | " + " | ".join(f"{f} (opt {summ[f]['mean_optimum']})" for f in fams) + " |",
              "| --- |" + " ---: |" * len(fams)]
    for name in VIEWS:
        cells = []
        for f in fams:
            a = summ[f][name]
            r, ci = a["needed_over_optimum"], a.get("needed_over_optimum_ci95")
            txt = "n/a" if r is None else f"{r:.2f}x" + (f" [{ci[0]:.2f}, {ci[1]:.2f}]" if ci else "")
            if a["never_rate"]:
                txt += f", never {a['never_rate']:.0%}"
            cells.append(txt)
        lines.append(f"| {LABEL[name]} | " + " | ".join(cells) + " |")
    lines += ["", "### Attacker cost gain where nothing disconnects", "",
              ("Rise of the attacker's cheapest-path cost (edge-cost units) after the 3 fixes, on topologies that stay "
               "connected (mean, 95% bootstrap interval, n)."), "",
              "| planner | " + " | ".join(fams) + " |", "| --- |" + " ---: |" * len(fams)]
    for name in VIEWS:
        cells = []
        for f in fams:
            a = summ[f][name]
            if a["cost_gain"] is None:
                cells.append("all disconnected")
                continue
            ci = a.get("cost_gain_ci95")
            cells.append(f"{a['cost_gain']:+.3f}" + (f" [{ci[0]:+.3f}, {ci[1]:+.3f}]" if ci else "")
                         + f" (n={a['cost_gain_n']})")
        lines.append(f"| {LABEL[name]} | " + " | ".join(cells) + " |")
    lines += ["", "### How much the exploit intel moves the path ranking", "",
              ("Uniform-cost view vs real costs on the same graph: Kendall tau between the real top-100 paths' real "
               "costs and their uniform-view costs, and the overlap of the two top-10 path sets (mean, 95% bootstrap "
               "interval)."), "", "| family | Kendall tau | top-10 overlap |", "| --- | ---: | ---: |"]
    for f in fams:
        u = summ[f]["uniform_cost_ranking"]

        def fmt(x, ci):
            return "n/a" if x is None else f"{x:.2f}" + (f" [{ci[0]:.2f}, {ci[1]:.2f}]" if ci else "")
        lines.append(f"| {f} | {fmt(u['kendall_tau'], u.get('kendall_tau_ci95'))} | "
                     f"{fmt(u['top10_overlap'], u.get('top10_overlap_ci95'))} |")
    return "\n".join(lines) + "\n"


def _task(a: tuple) -> dict:
    fam, seed, budget, k = a
    return run_one(fam, seed, hosts_for_seed(seed), budget, k)


def _clean(x):
    return None if isinstance(x, float) and math.isinf(x) else x


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--seeds", type=int, default=50)
    ap.add_argument("--budget", type=int, default=3)
    ap.add_argument("--k", type=int, default=100)
    ap.add_argument("--families", default=",".join(FAMILIES))
    ap.add_argument("--workers", type=int, default=1, help="parallel processes (results do not depend on it)")
    ap.add_argument("--out", default="benchmarks/results")
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    tasks = [(fam, seed, a.budget, a.k) for fam in a.families.split(",") for seed in range(a.seeds)]
    t0 = time.time()
    if a.workers > 1:
        with ProcessPoolExecutor(max_workers=a.workers) as ex:
            rows = list(ex.map(_task, tasks, chunksize=1))
    else:
        rows = [_task(t) for t in tasks]
    with (out / "ablation_rows.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    summ = summarise(rows)
    meta = {"seeds_per_family": a.seeds, "budget": a.budget, "k_cap": a.k, "long_budget": LONG_BUDGET,
            "hosts": f"{min(r['n_hosts'] for r in rows)}..{max(r['n_hosts'] for r in rows)} (12 + seed mod 49)",
            "cve_pool": pool_provenance(), "runtime_s": round(time.time() - t0, 1), "workers": a.workers,
            "platform": {"python": platform.python_version(), "machine": platform.machine(), "cpus": os.cpu_count()}}
    doc = json.loads(json.dumps({"meta": meta, "families": summ}, default=_clean))
    (out / "ablation.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")
    text = md(summ, a.budget, a.seeds)
    (out / "ablation.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
