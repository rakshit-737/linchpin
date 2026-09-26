"""M8: `linchpin` CLI (argparse, JSON to stdout). Offline: reads exported files only."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from linchpin.config import load_config
from linchpin.connectors import parse_any
from linchpin.engine.explain import explain_path
from linchpin.engine.optimizer import recommend
from linchpin.engine.paths import rank_paths
from linchpin.graph.store import GraphStore
from linchpin.models import NormalizedFinding
from linchpin.synth.generator import generate


def _state(args) -> Path:
    return Path(args.state)


def _load_store(args) -> GraphStore:
    cfg = load_config(args.config)
    sc = _state(args).parent / "config.json"
    if sc.exists():  # written by `linchpin scenario`
        from linchpin.config import Config
        cfg = Config.model_validate_json(sc.read_text())
    store = GraphStore(cfg)
    p = _state(args)
    if not p.exists():
        raise SystemExit(f"no findings ingested yet ({p}); run `linchpin ingest` first")
    store.upsert_findings(NormalizedFinding.model_validate(x) for x in json.loads(p.read_text()))
    store.build_attack_graph()
    return store


def _emit(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def cmd_synth(args) -> int:
    findings, gt = generate(args.hosts, 5, args.seed)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps([f.model_dump() for f in findings], indent=1))
    _emit({"findings": len(findings), "out": args.out, "ground_truth": gt.model_dump()})
    return 0


def cmd_ingest(args) -> int:
    from linchpin.connectors import bloodhound
    files: list[str] = []
    for p in args.paths:
        if os.path.isdir(p) and not bloodhound.is_bloodhound(p):
            files += sorted(str(x) for x in Path(p).iterdir()
                            if x.suffix.lower() in (".json", ".xml", ".nessus", ".yaml", ".yml") or
                            (x.is_dir() and bloodhound.is_bloodhound(x)))
        else:
            files.append(p)
    existing = {}
    st = _state(args)
    if args.replace:
        (st.parent / "config.json").unlink(missing_ok=True)  # drop a previous scenario's config
    if st.exists() and not args.replace:
        existing = {x["finding_id"]: x for x in json.loads(st.read_text())}
    n = 0
    parsed: list[NormalizedFinding] = []
    skipped = []
    for f in files:
        try:
            parsed += parse_any(f)
        except ValueError as e:
            skipped.append(str(e))
    intel_stats = None
    if args.intel:
        from linchpin.intel import CveIntel
        from linchpin.intel.enrich import enrich
        wanted = {c for x in parsed for c in [x.cve_id, *((x.detail or {}).get("cves") or [])] if c}
        parsed, intel_stats = enrich(parsed, CveIntel.load(args.intel, only=wanted))
    for finding in parsed:
        existing[finding.finding_id] = finding.model_dump()
        n += 1
    st.parent.mkdir(parents=True, exist_ok=True)
    st.write_text(json.dumps(list(existing.values())))
    _emit({"files": files, "skipped": skipped, "accepted": n, "total_findings": len(existing),
           "intel": intel_stats})
    return 0


def cmd_build(args) -> int:
    store = GraphStore(load_config(args.config))
    st = _state(args)
    if not st.exists():
        raise SystemExit("no findings ingested yet")
    store.upsert_findings(NormalizedFinding.model_validate(x) for x in json.loads(st.read_text()))
    _emit(store.build_attack_graph().model_dump())
    return 0


def cmd_paths(args) -> int:
    store = _load_store(args)
    paths = rank_paths(store, k=args.k)
    if args.explain:
        for p in paths:
            print(explain_path(p, store))
    else:
        _emit([p.model_dump() for p in paths])
    return 0


def cmd_fix(args) -> int:
    store = _load_store(args)
    _emit([r.model_dump() for r in recommend(store, budget=args.budget)])
    return 0


def cmd_whatif(args) -> int:
    store = _load_store(args)
    ids = [i if ":" in i or i == "internet" else f"host:{i}" for i in args.remove]
    _emit(store.remove_nodes_view(ids).model_dump())
    return 0


def cmd_node(args) -> int:
    store = _load_store(args)
    try:
        _emit(store.node(args.id).model_dump())
    except KeyError:
        print(f"unknown node {args.id}", file=sys.stderr)
        return 2
    return 0


def cmd_intel_build(args) -> int:
    from linchpin.intel import CveIntel
    out = args.out or str(Path(args.data_dir) / "derived" / "cve_intel.csv.gz")
    intel = CveIntel.build(args.data_dir, out)
    _emit({"out": out, **intel.meta})
    return 0


def cmd_scenario(args) -> int:
    from linchpin.scenario import load_scenario
    findings, cfg, stats = load_scenario(args.path, args.data_dir, use_intel=not args.no_intel)
    st = _state(args)
    st.parent.mkdir(parents=True, exist_ok=True)
    st.write_text(json.dumps([f.model_dump() for f in findings]))
    Path(st.parent / "config.json").write_text(cfg.model_dump_json())
    _emit(stats)
    return 0


def cmd_cuts(args) -> int:
    from linchpin.engine.cuts import chokepoints, min_remediation_cut
    store = _load_store(args)
    mc = min_remediation_cut(store)
    _emit({"chokepoints": chokepoints(store), "min_cut": mc, "min_cut_size": None if mc is None else len(mc)})
    return 0


def cmd_export(args) -> int:
    from linchpin.graph.neo4j_store import to_cypher
    store = _load_store(args)
    if args.format == "cypher":
        text = to_cypher(store.g, args.graph_name)
    else:
        import json as _json

        import networkx as nx
        h = nx.DiGraph()
        prim = (str, int, float, bool)
        for n, a in store.g.nodes(data=True):
            h.add_node(n, **{k: (v if isinstance(v, prim) else _json.dumps(v, default=str))
                             for k, v in a.items() if v is not None})
        for u, v, a in store.g.edges(data=True):
            h.add_edge(u, v, **{k: (x if isinstance(x, prim) else _json.dumps(x, default=str))
                                for k, x in a.items() if x is not None})
        text = "\n".join(nx.generate_graphml(h))
    Path(args.out).write_text(text, encoding="utf-8")
    _emit({"out": args.out, "nodes": store.g.number_of_nodes(), "edges": store.g.number_of_edges()})
    return 0


def cmd_neo4j_push(args) -> int:
    from linchpin.graph.neo4j_store import Neo4jGraphStore
    store = _load_store(args)
    pw = os.environ.get("NEO4J_PASSWORD")
    if not pw:
        raise SystemExit("set NEO4J_PASSWORD (and uri/user in config.yaml)")
    n4 = Neo4jGraphStore.connect(store.cfg, pw, graph_name=args.graph_name)
    n4.g = store.g
    _emit({"statements": n4.push(), "graph": args.graph_name})
    n4.close()
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="linchpin", description="Read-only attack-path reasoning (lab/synthetic data only).")
    ap.add_argument("--state", default=os.environ.get("LINCHPIN_STATE", ".linchpin/findings.json"))
    ap.add_argument("--config", default=os.environ.get("LINCHPIN_CONFIG", "config.yaml"))
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("synth", help="generate a synthetic enterprise")
    s.add_argument("--hosts", type=int, default=20)
    s.add_argument("--seed", type=int, default=0)
    s.add_argument("--out", default="data/synth.json")
    s.set_defaults(fn=cmd_synth)
    s = sub.add_parser("ingest", help="ingest exports (nmap/OpenVAS/Nessus XML, BloodHound JSON, "
                                      "inventory YAML, native JSON) from files or dirs")
    s.add_argument("paths", nargs="+")
    s.add_argument("--replace", action="store_true", help="discard previously ingested findings")
    s.add_argument("--intel", help="CVE intel cache (from `intel-build`) to enrich CVSS/EPSS/KEV")
    s.set_defaults(fn=cmd_ingest)
    s = sub.add_parser("intel-build", help="build the NVD/EPSS/KEV lookup cache from downloaded feeds")
    s.add_argument("--data-dir", default="../../datasets/linchpin")
    s.add_argument("--out")
    s.set_defaults(fn=cmd_intel_build)
    s = sub.add_parser("scenario", help="load a scenario YAML (real exports + topology overlay) as state")
    s.add_argument("path")
    s.add_argument("--data-dir")
    s.add_argument("--no-intel", action="store_true")
    s.set_defaults(fn=cmd_scenario)
    sub.add_parser("cuts", help="exact min remediation cut and single-node chokepoints").set_defaults(fn=cmd_cuts)
    s = sub.add_parser("export", help="export the attack graph (Neo4j .cypher script or GraphML)")
    s.add_argument("--format", choices=["cypher", "graphml"], default="cypher")
    s.add_argument("--out", required=True)
    s.add_argument("--graph-name", default="default")
    s.set_defaults(fn=cmd_export)
    s = sub.add_parser("neo4j-push", help="mirror the attack graph into Neo4j (NEO4J_PASSWORD env)")
    s.add_argument("--graph-name", default="default")
    s.set_defaults(fn=cmd_neo4j_push)
    sub.add_parser("build").set_defaults(fn=cmd_build)
    s = sub.add_parser("paths")
    s.add_argument("--k", type=int, default=10)
    s.add_argument("--explain", action="store_true")
    s.set_defaults(fn=cmd_paths)
    s = sub.add_parser("fix")
    s.add_argument("--budget", type=int, default=5)
    s.set_defaults(fn=cmd_fix)
    s = sub.add_parser("whatif")
    s.add_argument("--remove", nargs="+", required=True)
    s.set_defaults(fn=cmd_whatif)
    s = sub.add_parser("node")
    s.add_argument("id")
    s.set_defaults(fn=cmd_node)
    return ap


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
