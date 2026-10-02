"""Real-export case study: scenarios/composite_lab.yaml (see its header for provenance).

    python benchmarks/case_study.py --data-dir ../../datasets/linchpin

The findings and exploit intel are real public sample exports; the topology that places them
into one network is declared in the YAML. Writes benchmarks/results/case_study.{json,md}.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import networkx as nx

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from linchpin.benchmark import LABEL, evaluate, order
from linchpin.engine.cuts import chokepoints, min_remediation_cut
from linchpin.engine.optimizer import recommend
from linchpin.engine.paths import rank_paths
from linchpin.graph.store import GraphStore
from linchpin.intel.provenance import feed_provenance
from linchpin.scenario import load_scenario

STRATEGIES = ("linchpin", "milp_interdiction", "greedy_interdiction", "cvss", "cvss_reach", "epss", "epss_reach",
              "kev_epss", "kev_epss_reach", "betweenness")


def analyse(findings, cfg, budget, k):
    s = GraphStore(cfg)
    s.upsert_findings(findings)
    bs = s.build_attack_graph()
    base = evaluate(s, [], k)
    vulns = [a for _, a in s.g.nodes(data=True) if a.get("label") == "Vuln"]
    paths = s.k_shortest_paths(k=k)
    entries = s.entrypoints()
    reach = set(entries).union(*(nx.descendants(s.g, e) for e in entries)) if entries else set()
    aces = [n for n, a in s.g.nodes(data=True) if a.get("label") == "Ace"]
    res = {"nodes": bs.nodes, "edges": bs.edges, "vulns": len(vulns),
           "vulns_granting_privilege": sum(1 for n, a in s.g.nodes(data=True) if a.get("label") == "Vuln"
                                           and any(s.g.edges[n, v]["rel"] == "ENABLES" for v in s.g.successors(n))),
           "kev_vulns": sum(1 for a in vulns if a.get("kev")),
           "ace_nodes": len(aces), "ace_reachable_from_entry": sum(a in reach for a in aces),
           "ace_on_enumerated_paths": sum(any(a in p.nodes for p in paths) for a in aces),
           "credential_uses_unreachable": sum(1 for _, _, a in s.g.edges(data=True)
                                              if a["rel"] == "GRANTS" and "prerequisite_match" in a),
           "crown_jewels": s.crown_jewels(), "paths_enumerated": base["residual"], "min_cost": base["min_cost"],
           "chokepoints": chokepoints(s), "min_cut": min_remediation_cut(s)}
    res["top_paths"] = [{"cost": p.total_cost, "hops": [n for n in p.nodes if n.split(":")[0] in
                                                         ("internet", "host", "cred", "vuln", "ds")]}
                        for p in rank_paths(s, k=3)]
    res["linchpin_plan"] = [{"node": r.target_node, "action": r.action, "rationale": r.rationale,
                             "paths_broken": r.paths_broken, "paths_total": r.paths_total}
                            for r in recommend(s, budget=budget, k=k)]
    res["strategies"] = {}
    for strat in STRATEGIES:
        rem = order(s, strat, budget, k=k)
        ev = evaluate(s, rem, k)
        res["strategies"][strat] = {"fixes": rem, "disconnected": ev["disconnected"], "residual": ev["residual"],
                                    "min_cost_after": None if ev["disconnected"] else ev["min_cost"]}
    return res


def table(r: dict, budget: int, k: int) -> list[str]:
    lines = [f"| strategy (budget {budget}) | fixes chosen | crown jewel cut off? | residual paths (k={k}) |",
             "| --- | --- | :---: | ---: |"]
    for name, v in r["strategies"].items():
        fixes = "<br>".join(f"`{x}`" for x in v["fixes"]) or "-"
        lines.append(f"| {LABEL[name]} | {fixes} | {'yes' if v['disconnected'] else 'no'} | {v['residual']} |")
    return lines


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--scenario", default="scenarios/composite_lab.yaml")
    ap.add_argument("--data-dir", default="../../datasets/linchpin")
    ap.add_argument("--budget", type=int, default=3)
    ap.add_argument("--k", type=int, default=200)
    ap.add_argument("--out", default="benchmarks/results")
    a = ap.parse_args(argv)
    findings, cfg, stats = load_scenario(a.scenario, a.data_dir)
    out = {"scenario": stats, "provenance": feed_provenance(a.data_dir), "intel": analyse(findings, cfg, a.budget, a.k)}
    if stats.get("intel", {}).get("learned_model"):
        out["learned"] = analyse(findings, cfg.model_copy(update={"exploitability_source": "learned"}),
                                 a.budget, a.k)
    raw, cfg_raw, _ = load_scenario(a.scenario, a.data_dir, use_intel=False)
    out["scanner_only"] = analyse(raw, cfg_raw, a.budget, a.k)
    d = Path(a.out)
    d.mkdir(parents=True, exist_ok=True)
    (d / "case_study.json").write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
    r = out["intel"]
    exported = sum(stats["sources"].values())
    lines = [
        f"Findings: {stats['findings']} = {exported} from {len(stats['sources'])} real exports + "
        f"{stats['overlay_findings']} from the declared topology overlay (hosts, firewall rules, one service "
        f"account); {stats['intel'].get('enriched', 0)}/{stats['intel'].get('cve_findings', 0)} vuln findings carry "
        f"a CVE found in NVD (the rest are CVE-less checks) (EPSS {stats['intel'].get('epss_date', '')[:10]}), "
        f"{r['kev_vulns']} in CISA KEV.",
        f"Attack graph: {r['nodes']} nodes, {r['edges']} edges; {r['vulns']} vuln nodes of which "
        f"{r['vulns_granting_privilege']} grant code execution; {r['paths_enumerated']} crown-jewel paths "
        f"enumerated (k cap {a.k}); cheapest path cost {r['min_cost']:.3f}. {r['ace_nodes']} abusable-ACE nodes: "
        f"{r['ace_reachable_from_entry']} reachable from the entry points, {r['ace_on_enumerated_paths']} on an "
        f"enumerated path to the crown jewel. {r['credential_uses_unreachable']} credential uses target hosts the "
        "declared firewall rules do not reach (scored with prerequisite_match < 1, contract v1.3).",
        f"Single-node chokepoints: {', '.join(r['chokepoints']) or 'none'}. Exact min cut: {r['min_cut']}.", "",
        "With NVD / EPSS / KEV enrichment:", "", *table(r, a.budget, a.k), "",
        "LINCHPIN rationale for its first fix:", "",
        f"> {r['linchpin_plan'][0]['rationale']}" if r["linchpin_plan"] else "> (no viable path)"]
    if "learned" in out:
        lp = out["learned"]["linchpin_plan"]
        lines += ["", f"M11 learned exploitability instead of CVSS/EPSS/KEV: first fix "
                      f"`{lp[0]['node'] if lp else '-'}`, cheapest path cost {out['learned']['min_cost']:.3f}."]
    so = out["scanner_only"]
    lines += ["", (f"Scanner scores only (no NVD/EPSS/KEV enrichment; {so['vulns_granting_privilege']} vulns grant "
                   f"code execution, cheapest path cost {so['min_cost']:.3f}). Without EPSS data only findings whose "
                   "export carries an EPSS value can be ranked by EPSS, which is why the EPSS queues differ:"), "",
              *table(so, a.budget, a.k)]
    (d / "case_study.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
