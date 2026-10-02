"""Measured case study: LINCHPIN on a scan of vulnerable containers started inside CI.

The ``lab-scan`` CI job (lab/up.sh, lab/scan.sh) starts official images pinned to older
releases (httpd 2.4.49, nginx 1.16.1, tomcat 9.0.30, redis 5.0.7, mysql 5.5.62) on two
``--internal`` Docker networks and runs ``nmap -sV`` (version detection only, no NSE scripts)
from a scanner container inside each network. This script turns that measurement into a plan:

1. **Topology from the measurement.** One host per container (its IPs on each network are
   merged with ``match:``); its segment is the set of networks it is attached to; an allow
   rule wherever a scanner on one segment's network saw a port open on a host of another
   segment. Declared, because a scan cannot observe them: the ``lp-dmz`` network faces the
   internet, and the ``db`` container holds the crown-jewel customer database.
2. **Versions -> CVEs offline** with the packaged NVD version-range index and its CVSS / EPSS /
   KEV values (linchpin.intel.cpe); no network lookups.
3. **Plans** at budget 1 and 3 from LINCHPIN and the comparison planners of the synthetic
   benchmark, scored on the measured graph, plus the fixes each needs to cut the database off.

    python benchmarks/lab_case_study.py --scans artifacts/lab            # in CI, after lab/scan.sh
    python benchmarks/lab_case_study.py --scans benchmarks/results/lab   # replay the committed scan

Exits non-zero if a check fails (no NSE output, >= 3 versions detected, a KEV CVE mapped, the
database reachable before and cut off by LINCHPIN's plan, LINCHPIN never needs more fixes than
a baseline). Writes lab_case_study.{json,md} and the derived topology.yaml next to the scans.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from linchpin.benchmark import LABEL, evaluate, order
from linchpin.connectors import CONNECTORS
from linchpin.connectors.inventory import aliases, from_doc
from linchpin.engine.cuts import chokepoints, min_remediation_cut
from linchpin.engine.optimizer import recommend
from linchpin.graph.store import GraphStore
from linchpin.intel.cpe import CpeIndex, match_services
from linchpin.scenario import apply_aliases

NETWORKS = ("lp-dmz", "lp-core")  # order defines the segment names, e.g. "dmz+core"
INTERNET_FACING_NETWORK = "lp-dmz"  # declared
CROWN = {"db": [{"name": "customer-db", "sensitivity": "high"}]}  # declared
STRATEGIES = ("linchpin", "milp_interdiction", "greedy_interdiction", "cvss", "cvss_reach", "epss", "epss_reach",
              "kev_epss", "kev_epss_reach", "betweenness")


def derive_topology(scans: Path) -> tuple[dict, list]:
    """Topology YAML document from `docker network inspect` plus the per-network scans."""
    nets = json.loads((scans / "networks.json").read_text(encoding="utf-8"))
    attached: dict[str, dict[str, str]] = {}  # container -> {network: ip}
    for n in nets:
        for c in (n.get("Containers") or {}).values():
            attached.setdefault(c["Name"], {})[n["Name"]] = c["IPv4Address"].split("/")[0]
    seg = {c: "+".join(x.removeprefix("lp-") for x in NETWORKS if x in nw) for c, nw in attached.items()}
    by_ip = {ip: c for c, nw in attached.items() for ip in nw.values()}
    hosts = [{"id": c, "match": sorted(nw.values()), "segment": seg[c],
              "internet_facing": INTERNET_FACING_NETWORK in nw, "datastores": CROWN.get(c, [])}
             for c, nw in sorted(attached.items())]
    rules: dict[tuple[str, str], set[int]] = {}
    findings = []
    for net in NETWORKS:
        got = CONNECTORS["nmap"](str(scans / f"scan-{net}.xml"))
        findings += got
        vantage = {seg[c] for c, nw in attached.items() if net in nw}
        for f in got:
            target = by_ip.get(f.detail.get("ip") or f.host_id)
            if f.kind != "service" or target is None:
                continue
            for s in vantage:
                if s != seg[target]:
                    rules.setdefault((s, seg[target]), set()).add(f.port)
    doc = {"name": "ci-lab-measured", "hosts": hosts,
           "reachability": [{"from": a, "to": b, "ports": sorted(p)} for (a, b), p in sorted(rules.items())],
           "crown_jewels": ["auto:sensitivity=high"], "entrypoints": ["auto:internet_facing"], "k_shortest": 100}
    return doc, findings


def needed(store: GraphStore, strategy: str, cap: int = 6) -> int | None:
    """Fewest of the strategy's fixes that cut every crown jewel off (None: not within ``cap``)."""
    if strategy == "milp_interdiction":  # a set per budget, not an ordered list: re-solve per budget
        return next((b for b in range(1, cap + 1)
                     if not store.reachable_crown_jewels(exclude=order(store, strategy, b, k=100))), None)
    rem = order(store, strategy, cap, k=100)
    for i in range(1, len(rem) + 1):
        if not store.reachable_crown_jewels(exclude=rem[:i]):
            return i
    return None


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--scans", default="benchmarks/results/lab")
    ap.add_argument("--out", help="output folder (default: --scans)")
    a = ap.parse_args(argv)
    scans = Path(a.scans)
    out = Path(a.out or a.scans)
    out.mkdir(parents=True, exist_ok=True)
    checks: dict[str, bool] = {}
    xml = "".join((scans / f"scan-{n}.xml").read_text(encoding="utf-8") for n in NETWORKS)
    checks["no NSE script output in the scans"] = "<script " not in xml

    topo, raw = derive_topology(scans)
    (out / "topology.yaml").write_text(yaml.safe_dump(topo, sort_keys=False), encoding="utf-8")
    services = apply_aliases([f for f in raw if f.kind == "service"], aliases(topo))
    detected = sorted({f"{f.software} {f.version}" for f in services if f.software and f.version})
    checks[">= 3 product versions detected"] = len(detected) >= 3
    index = CpeIndex.load()
    cve_findings, cpe_stats = match_services(services, index)
    checks["a CISA KEV CVE was mapped"] = cpe_stats["kev_cves"] > 0
    findings = services + cve_findings + from_doc(topo)

    store = GraphStore(GraphStore().cfg.model_copy(update={"k_shortest": 100}))
    store.upsert_findings(findings)
    bs = store.build_attack_graph()
    base = evaluate(store, [], 100)
    crown = store.crown_jewels()
    checks["crown jewel reachable before any fix"] = bool(store.reachable_crown_jewels())
    res: dict = {
        "detected": detected, "cpe_match": cpe_stats, "topology": topo,
        "graph": {"nodes": bs.nodes, "edges": bs.edges, "crown_jewels": crown,
                  "paths_before": base["residual"], "cheapest_path_cost": base["min_cost"]},
        "vulns": [{"node": n, "host": a.get("host_id"), "name": a.get("name"), "cvss": a.get("cvss_base"),
                   "epss": a.get("epss"), "kev": a.get("kev"), "grants_code_execution": any(
                       store.g.edges[n, v]["rel"] == "ENABLES" for v in store.g.successors(n))}
                  for n, a in store.g.nodes(data=True) if a.get("label") == "Vuln"],
        "chokepoints": chokepoints(store), "min_cut": min_remediation_cut(store),
        "plan": [{"node": r.target_node, "action": r.action, "rationale": r.rationale, "paths_broken": r.paths_broken,
                  "paths_total": r.paths_total} for r in recommend(store, budget=3, k=100)],
        "strategies": {},
    }
    for s in STRATEGIES:
        row = {"fixes_to_disconnect": needed(store, s)}
        for budget in (1, 3):
            rem = order(store, s, budget, k=100)
            ev = evaluate(store, rem, 100)
            row[f"budget_{budget}"] = {"fixes": rem, "disconnected": ev["disconnected"], "residual": ev["residual"],
                                       "min_cost_after": None if ev["disconnected"] else ev["min_cost"]}
        res["strategies"][s] = row
    lp = res["strategies"]["linchpin"]
    checks["LINCHPIN's plan cuts the crown jewel off within budget 3"] = bool(lp["budget_3"]["disconnected"])
    checks["LINCHPIN never needs more fixes than a baseline"] = all(
        v["fixes_to_disconnect"] is None or (lp["fixes_to_disconnect"] or 99) <= v["fixes_to_disconnect"]
        for v in res["strategies"].values())
    res["checks"] = checks
    versions = scans / "versions.txt"
    res["tools"] = versions.read_text(encoding="utf-8").strip().splitlines() if versions.exists() else []
    res["cpe_index"] = index.meta[:200]
    (out / "lab_case_study.json").write_text(json.dumps(res, indent=2, default=str), encoding="utf-8")
    text = render(res)
    (out / "lab_case_study.md").write_text(text, encoding="utf-8")
    print(text)
    failed = [k for k, ok in checks.items() if not ok]
    if failed:
        print("FAILED: " + "; ".join(failed), file=sys.stderr)
        return 1
    return 0


def render(res: dict) -> str:
    g = res["graph"]
    cm = res["cpe_match"]
    lines = [f"Detected by `nmap -sV` (no scripts): {', '.join(res['detected'])}.", "",
             f"Offline NVD version-range matching: {cm['matched_services']} of {cm['services']} services matched, "
             f"{cm['cves']} CVEs, {cm['kev_cves']} of them in CISA KEV. Attack graph: {g['nodes']} nodes, "
             f"{g['edges']} edges, {g['paths_before']} entry -> crown-jewel paths (k cap 100); crown jewel "
             f"{', '.join(g['crown_jewels'])}.", "",
             "| vuln node (one per service: upgrade it) | CVSS | EPSS | KEV | code execution |",
             "| --- | ---: | ---: | :---: | :---: |"]
    for v in sorted(res["vulns"], key=lambda v: v["node"]):
        lines.append(f"| {v['name']} on `{v['host']}` | {v['cvss']} | {v['epss']} | {'yes' if v['kev'] else ''} | "
                     f"{'yes' if v['grants_code_execution'] else 'no'} |")
    lines += ["", f"Chokepoints: {', '.join(f'`{c}`' for c in res['chokepoints']) or 'none'}; exact min cut "
                  f"{res['min_cut']} (one of several minimum cuts: every chokepoint above is a one-node cut). "
                  "recommend() keeps the greedy pick when it is already a cut of minimum size, preferring the node on "
                  "the most enumerated paths, then the node id; the MILP may return a different minimum cut of the same size.", "",
              "| strategy | 1 fix: chosen | cut off? | 3 fixes: cut off? | fixes needed to cut off |",
              "| --- | --- | :---: | :---: | ---: |"]
    for s, r in res["strategies"].items():
        b1, b3 = r["budget_1"], r["budget_3"]
        lines.append(f"| {LABEL[s]} | {', '.join(f'`{x}`' for x in b1['fixes']) or '-'} | "
                     f"{'yes' if b1['disconnected'] else 'no'} | {'yes' if b3['disconnected'] else 'no'} | "
                     f"{r['fixes_to_disconnect'] or 'never (6 tried)'} |")
    if res["plan"]:
        lines += ["", "LINCHPIN's rationale for its first fix:", "", f"> {res['plan'][0]['rationale']}"]
    lines += ["", "Checks: " + "; ".join(f"{k}: {'pass' if ok else 'FAIL'}" for k, ok in res["checks"].items()) + ".",
              *(["", "Tools: " + "; ".join(res["tools"]) + "."] if res["tools"] else [])]
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    raise SystemExit(main())
