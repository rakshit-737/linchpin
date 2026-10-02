"""Real-export case study: scenarios/composite_lab.yaml (see its header for provenance).

    python benchmarks/case_study.py --data-dir ../../datasets/linchpin

Writes benchmarks/results/case_study.{json,md}.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from linchpin.benchmark import evaluate, order
from linchpin.engine.cuts import chokepoints, min_remediation_cut
from linchpin.engine.optimizer import recommend
from linchpin.engine.paths import rank_paths
from linchpin.graph.store import GraphStore
from linchpin.scenario import load_scenario


def analyse(findings, cfg, budget, k):
    s = GraphStore(cfg)
    s.upsert_findings(findings)
    bs = s.build_attack_graph()
    base = evaluate(s, [], k)
    vulns = [a for _, a in s.g.nodes(data=True) if a.get("label") == "Vuln"]
    res = {"nodes": bs.nodes, "edges": bs.edges, "vulns": len(vulns),
           "vulns_granting_privilege": sum(1 for n, a in s.g.nodes(data=True) if a.get("label") == "Vuln"
                                           and any(s.g.edges[n, v]["rel"] == "ENABLES" for v in s.g.successors(n))),
           "kev_vulns": sum(1 for a in vulns if a.get("kev")),
           "crown_jewels": s.crown_jewels(), "paths_enumerated": base["residual"], "min_cost": base["min_cost"],
           "chokepoints": chokepoints(s), "min_cut": min_remediation_cut(s)}
    res["top_paths"] = [{"cost": p.total_cost, "hops": [n for n in p.nodes if n.split(":")[0] in
                                                         ("internet", "host", "cred", "vuln", "ds")]}
                        for p in rank_paths(s, k=3)]
    res["linchpin_plan"] = [{"node": r.target_node, "action": r.action, "rationale": r.rationale,
                             "paths_broken": r.paths_broken, "paths_total": r.paths_total}
                            for r in recommend(s, budget=budget, k=k)]
    res["strategies"] = {}
    for strat in ("linchpin", "cvss", "epss", "kev_epss", "betweenness"):
        rem = order(s, strat, budget, k=k)
        ev = evaluate(s, rem, k)
        res["strategies"][strat] = {"fixes": rem, "disconnected": ev["disconnected"], "residual": ev["residual"],
                                    "min_cost_after": None if ev["disconnected"] else ev["min_cost"]}
    return res


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="scenarios/composite_lab.yaml")
    ap.add_argument("--data-dir", default="../../datasets/linchpin")
    ap.add_argument("--budget", type=int, default=3)
    ap.add_argument("--k", type=int, default=200)
    ap.add_argument("--out", default="benchmarks/results")
    a = ap.parse_args(argv)
    findings, cfg, stats = load_scenario(a.scenario, a.data_dir)
    out = {"scenario": stats, "intel": analyse(findings, cfg, a.budget, a.k)}
    if stats.get("intel", {}).get("learned_model"):
        out["learned"] = analyse(findings, cfg.model_copy(update={"exploitability_source": "learned"}),
                                 a.budget, a.k)
    _, cfg_raw, _ = load_scenario(a.scenario, a.data_dir, use_intel=False)
    raw, _, _ = load_scenario(a.scenario, a.data_dir, use_intel=False)
    out["scanner_only"] = analyse(raw, cfg_raw, a.budget, a.k)
    d = Path(a.out)
    d.mkdir(parents=True, exist_ok=True)
    (d / "case_study.json").write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    r = out["intel"]
    lines = [
        f"Findings: {stats['findings']} from {len(stats['sources'])} real exports; "
        f"{stats['intel'].get('enriched', 0)}/{stats['intel'].get('cve_findings', 0)} vuln findings carry a CVE "
        "found in NVD (the rest are CVE-less checks) "
        f"(EPSS {stats['intel'].get('epss_date', '')[:10]}), {r['kev_vulns']} in CISA KEV.",
        f"Attack graph: {r['nodes']} nodes, {r['edges']} edges; {r['vulns']} vuln nodes of which "
        f"{r['vulns_granting_privilege']} grant code execution; {r['paths_enumerated']} crown-jewel paths "
        f"enumerated (k cap {a.k}); cheapest path cost {r['min_cost']:.3f}.",
        f"Single-node chokepoints: {', '.join(r['chokepoints']) or 'none'}. Exact min cut: "
        f"{r['min_cut']}.", "",
        f"| strategy (budget {a.budget}) | fixes chosen | crown jewel cut off? | residual paths |",
        "| --- | --- | :---: | ---: |"]
    for name, v in r["strategies"].items():
        fixes = "<br>".join(f"`{x}`" for x in v["fixes"])
        lines.append(f"| {name} | {fixes} | {'yes' if v['disconnected'] else 'no'} | {v['residual']} |")
    lines += ["", "LINCHPIN rationale for its first fix:", "", f"> {r['linchpin_plan'][0]['rationale']}"
              if r["linchpin_plan"] else "> (no viable path)"]
    if "learned" in out:
        lp = out["learned"]["linchpin_plan"]
        lines += ["", f"Ablation, M11 learned exploitability instead of CVSS/EPSS/KEV: first fix "
                      f"`{lp[0]['node'] if lp else '-'}`, cheapest path cost {out['learned']['min_cost']:.3f}."]
    so = out["scanner_only"]
    lines += [f"Ablation, scanner scores only (no NVD/EPSS/KEV enrichment): first fix "
              f"`{so['linchpin_plan'][0]['node'] if so['linchpin_plan'] else '-'}`, cheapest path cost "
              f"{so['min_cost']:.3f}, {so['vulns_granting_privilege']} vulns granting code execution."]
    (d / "case_study.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
