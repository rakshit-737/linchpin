"""M8: `linchpin` CLI (argparse, JSON to stdout). Offline: reads exported files only.

State lives in ``--state`` (default ``.linchpin/findings.json``): ``ingest`` / ``scenario``
write it, every analysis command reads it and rebuilds the attack graph deterministically.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from linchpin import __version__
from linchpin.config import Config, load_config
from linchpin.connectors import CONNECTORS, detect
from linchpin.engine.explain import explain_path
from linchpin.engine.optimizer import recommend
from linchpin.engine.paths import rank_paths
from linchpin.graph.store import GraphStore
from linchpin.models import NormalizedFinding

LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _state(args) -> Path:
    return Path(args.state)


def _config(args) -> Config:
    """Config from --config, overridden by the one a `linchpin scenario` run stored next to the state."""
    sc = _state(args).parent / "config.json"
    if sc.exists():
        return Config.model_validate_json(sc.read_text(encoding="utf-8"))
    return load_config(args.config)


def _findings(args) -> list[NormalizedFinding]:
    p = _state(args)
    if not p.exists():
        raise SystemExit(f"no findings ingested yet ({p}); run `linchpin ingest <files>` or "
                         "`linchpin scenario <yaml>` first")
    return [NormalizedFinding.model_validate(x) for x in json.loads(p.read_text(encoding="utf-8"))]


def _load_store(args) -> GraphStore:
    store = GraphStore(_config(args))
    store.upsert_findings(_findings(args))
    store.build_attack_graph()
    return store


def _emit(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _warn(msg: str) -> None:
    print(f"linchpin: warning: {msg}", file=sys.stderr)


def _reach_summary(store: GraphStore) -> dict:
    return {"nodes": store.g.number_of_nodes(), "edges": store.g.number_of_edges(),
            "entrypoints": store.entrypoints(), "crown_jewels": store.crown_jewels(),
            "reachable_crown_jewels": store.reachable_crown_jewels()}


def _diagnose(store: GraphStore) -> None:
    """Explain on stderr why there is nothing to rank (an empty plan must not read as 'all clear')."""
    if not store.entrypoints():
        _warn("no entry point in the graph: mark internet-facing hosts in a topology YAML "
              "(internet_facing: true) or list entry hosts under `entrypoints` in the config")
    if not store.crown_jewels():
        _warn("no crown jewel in the graph: declare a datastore with sensitivity: high on a host in a "
              "topology YAML, or list crown jewels under `crown_jewels` in the config")
    if store.entrypoints() and store.crown_jewels() and not store.reachable_crown_jewels():
        _warn("no crown jewel is reachable from the entry points. If that is unexpected, check that the "
              "topology's host ids match the scanners' (list scanner ids under the host's `match:`) and "
              "that reachability rules connect the segments")


def cmd_synth(args) -> int:
    """``linchpin synth``: write a seeded synthetic topology and its ground truth."""
    if args.family == "legacy":
        from linchpin.synth.generator import generate
        findings, gt = generate(args.hosts, 5, args.seed)
    else:
        from linchpin.synth.topologies import generate_family
        findings, gt = generate_family(args.family, args.hosts, args.seed)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps([f.model_dump() for f in findings], indent=1), encoding="utf-8")
    _emit({"findings": len(findings), "out": args.out, "ground_truth": gt.model_dump()})
    return 0


def cmd_ingest(args) -> int:
    """``linchpin ingest``: parse exports (and a topology YAML) into the state file."""
    from linchpin.connectors import bloodhound, inventory
    from linchpin.scenario import CONFIG_KEYS, apply_aliases
    files: list[str] = []
    missing = [p for p in args.paths if not os.path.exists(p)]
    if missing:
        raise SystemExit(f"ingest: no such file or directory: {', '.join(missing)}")
    for p in args.paths:
        if os.path.isdir(p) and not bloodhound.is_bloodhound(p):
            files += sorted(str(x) for x in Path(p).iterdir()
                            if x.suffix.lower() in (".json", ".xml", ".nessus", ".yaml", ".yml") or
                            (x.is_dir() and bloodhound.is_bloodhound(x)))
        else:
            files.append(p)
    existing = {}
    st = _state(args)
    if st.exists() and not args.replace:
        existing = {x["finding_id"]: x for x in json.loads(st.read_text(encoding="utf-8"))}
    n = 0
    parsed: list[NormalizedFinding] = []
    skipped = []
    alias: dict[str, str] = {}
    overrides: dict = {}
    for f in files:
        try:
            name = detect(f)
            if name == "inventory":  # topology overlay: host aliases and config overrides apply to all inputs
                doc = inventory.load(f)
                alias.update(inventory.aliases(doc))
                overrides.update({k: doc[k] for k in CONFIG_KEYS if k in doc})
            parsed += CONNECTORS[name](f)
        except ValueError as e:  # unsafe or malformed input (connectors raise ValueError naming the file)
            skipped.append(str(e))
        except (KeyError, TypeError, AttributeError) as e:  # well-formed, but not the structure expected
            skipped.append(f"{f}: unexpected content ({type(e).__name__}: {e})")
    if files and len(skipped) == len(files):  # nothing usable: leave the state (and its config) untouched
        _emit({"files": files, "skipped": skipped, "accepted": 0})
        print(f"ingest: none of the {len(files)} input(s) could be read; the state was not changed", file=sys.stderr)
        return 1
    unmatched: list[str] = []
    if alias:
        scanner_hosts = {x.host_id for x in parsed} | {x["host_id"] for x in existing.values()}
        unmatched = sorted(a for a in alias if a not in scanner_hosts)
        parsed = apply_aliases(parsed, alias)
        old = apply_aliases([NormalizedFinding.model_validate(x) for x in existing.values()], alias)
        existing = {x.finding_id: x.model_dump() for x in old}
        for a in unmatched:
            _warn(f"topology alias {a!r} (match:) matches no host id in the exports")
    cpe_stats = None
    if args.match_cpe:  # map detected product versions to CVEs offline (NVD version ranges)
        from linchpin.intel.cpe import match_services
        matched, cpe_stats = match_services(parsed)
        parsed += matched
    intel_stats = None
    if args.intel and not os.path.exists(args.intel):
        raise SystemExit(f"ingest: intel cache not found: {args.intel} (build it with `linchpin intel-build`)")
    if args.intel:
        from linchpin.intel import CveIntel
        from linchpin.intel.enrich import enrich
        wanted = {c for x in parsed for c in [x.cve_id, *((x.detail or {}).get("cves") or [])] if c}
        parsed, intel_stats = enrich(parsed, CveIntel.load(args.intel, only=wanted))
    for finding in parsed:
        existing[finding.finding_id] = finding.model_dump()
        n += 1
    st.parent.mkdir(parents=True, exist_ok=True)
    if args.replace:  # drop a previous scenario's config, only once the new inputs parsed
        (st.parent / "config.json").unlink(missing_ok=True)
    st.write_text(json.dumps(list(existing.values())), encoding="utf-8")
    cfg = _config(args)
    if overrides:  # same mechanism as `linchpin scenario`: config stored next to the state
        cfg = cfg.model_copy(update=overrides)
        (st.parent / "config.json").write_text(cfg.model_dump_json(), encoding="utf-8")
    store = GraphStore(cfg)
    store.upsert_findings(NormalizedFinding.model_validate(x) for x in existing.values())
    store.build_attack_graph()
    _diagnose(store)
    _emit({"files": files, "skipped": skipped, "accepted": n, "total_findings": len(existing),
           "aliases": len(alias), "unmatched_aliases": unmatched, "cpe_match": cpe_stats, "intel": intel_stats,
           "graph": _reach_summary(store)})
    return 0


def cmd_build(args) -> int:
    """``linchpin build``: build the attack graph and print its size."""
    store = GraphStore(_config(args))
    store.upsert_findings(_findings(args))
    _emit(store.build_attack_graph().model_dump())
    return 0


def cmd_paths(args) -> int:
    """``linchpin paths``: the k cheapest entry-to-crown-jewel attack paths."""
    store = _load_store(args)
    paths = rank_paths(store, k=args.k)
    if not paths:
        _diagnose(store)
    if args.explain:
        for p in paths:
            print(explain_path(p, store))
    else:
        _emit([p.model_dump() for p in paths])
    return 0


def cmd_fix(args) -> int:
    """``linchpin fix``: the budgeted remediation plan with rationale and evidence."""
    store = _load_store(args)
    plan = recommend(store, budget=args.budget)
    if not plan:
        _diagnose(store)
    _emit([r.model_dump() for r in plan])
    return 0


def cmd_whatif(args) -> int:
    """``linchpin whatif``: path statistics with nodes removed."""
    store = _load_store(args)
    ids = [i if ":" in i or i == "internet" else f"host:{i}" for i in args.remove]
    unknown = [i for i in ids if i not in store.g]
    if unknown:
        print(f"unknown node(s) {', '.join(repr(i) for i in unknown)}; node ids look like host:<id>, "
              "vuln:<key>@<host>:<port>, cred:<principal>, ds:<name> (see `linchpin paths`)", file=sys.stderr)
        return 2
    _emit(store.remove_nodes_view(ids).model_dump())
    return 0


def cmd_node(args) -> int:
    """``linchpin node``: one node with its attack edges."""
    store = _load_store(args)
    try:
        _emit(store.node(args.id).model_dump())
    except KeyError:
        print(f"unknown node {args.id!r}; node ids look like host:<id>, vuln:<key>@<host>:<port>, "
              "cred:<principal>, ds:<name> (see `linchpin paths`)", file=sys.stderr)
        return 2
    return 0


def cmd_intel_build(args) -> int:
    """``linchpin intel-build``: build the NVD / EPSS / KEV lookup cache."""
    from linchpin.intel import CveIntel
    if not (Path(args.data_dir) / "nvd").is_dir():
        raise SystemExit(f"intel-build: {args.data_dir} has no nvd/ folder; run scripts/download_data.py first")
    out = args.out or str(Path(args.data_dir) / "derived" / "cve_intel.csv.gz")
    intel = CveIntel.build(args.data_dir, out)
    _emit({"out": out, **intel.meta})
    return 0


def cmd_scenario(args) -> int:
    """``linchpin scenario``: load a scenario YAML (exports, topology, intel) as the state."""
    from linchpin.scenario import load_scenario
    if not os.path.isfile(args.path):
        raise SystemExit(f"scenario: no such file: {args.path}")
    try:
        findings, cfg, stats = load_scenario(args.path, args.data_dir, use_intel=not args.no_intel)
    except FileNotFoundError as e:
        raise SystemExit(f"scenario: export listed in {args.path} not found: {e.filename} "
                         "(pass --data-dir, or run scripts/download_data.py)") from None
    st = _state(args)
    st.parent.mkdir(parents=True, exist_ok=True)
    st.write_text(json.dumps([f.model_dump() for f in findings]), encoding="utf-8")
    Path(st.parent / "config.json").write_text(cfg.model_dump_json(), encoding="utf-8")
    _emit(stats)
    return 0


def cmd_cuts(args) -> int:
    """``linchpin cuts``: chokepoints and the exact (optionally effort-weighted) minimum cut."""
    from linchpin.engine.cuts import chokepoints, fix_cost, min_remediation_cut
    store = _load_store(args)
    mc = min_remediation_cut(store)
    out = {"chokepoints": chokepoints(store), "min_cut": mc, "min_cut_size": None if mc is None else len(mc)}
    if getattr(args, "weighted", False):
        wc = min_remediation_cut(store, weighted=True)
        out["weighted_cut"] = wc
        out["weighted_cut_effort"] = None if wc is None else sum(fix_cost(store, n) for n in wc)
        out["min_cut_effort"] = None if mc is None else sum(fix_cost(store, n) for n in mc)
    _emit(out)
    return 0


def cmd_export(args) -> int:
    """``linchpin export``: write the attack graph as a Cypher script or GraphML."""
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
    """``linchpin neo4j-push``: mirror the attack graph into Neo4j."""
    try:
        import neo4j  # noqa: F401  (optional dependency, imported only to give a clear error)

        from linchpin.graph.neo4j_store import Neo4jGraphStore
    except ImportError:
        raise SystemExit("neo4j-push needs the Neo4j driver: install the [neo4j] extra (in a checkout: "
                         "pip install -e '.[neo4j]'; PyPI's 'linchpin' is an unrelated project)") from None
    store = _load_store(args)
    pw = os.environ.get("NEO4J_PASSWORD")
    if not pw:
        raise SystemExit("set NEO4J_PASSWORD (and neo4j.uri / neo4j.user in config.yaml)")
    from neo4j.exceptions import AuthError, ServiceUnavailable
    uri = store.cfg.neo4j.get("uri", "bolt://localhost:7687")
    try:
        n4 = Neo4jGraphStore.connect(store.cfg, pw, graph_name=args.graph_name)
        n4.g = store.g
        _emit({"statements": n4.push(), "graph": args.graph_name})
        n4.close()
    except AuthError as e:
        raise SystemExit(f"neo4j-push: authentication failed at {uri}: {e.message}") from None
    except ServiceUnavailable as e:
        raise SystemExit(f"neo4j-push: cannot reach Neo4j at {uri}: {e}") from None
    return 0


def cmd_serve(args) -> int:
    """``linchpin serve``: run the API and web UI (localhost by default)."""
    try:
        import uvicorn
    except ImportError:
        raise SystemExit("serve needs the API extra: pip install \"linchpin-attackpath[api] @ "
                         "git+https://github.com/rakshit-737/linchpin\" (in a checkout: pip install -e '.[api]'; "
                         "PyPI's 'linchpin' is an unrelated project)") from None
    if args.host not in LOOPBACK:
        print(f"WARNING: binding to {args.host}. The API has no authentication and serves a map of your "
              "weaknesses; keep it on a trusted, isolated network.", file=sys.stderr)
    if args.scenario:
        os.environ["LINCHPIN_SCENARIO"] = str(Path(args.scenario).resolve())
    if args.data_dir:
        os.environ["LINCHPIN_DATA_DIR"] = str(Path(args.data_dir).resolve())
    host = f"[{args.host}]" if ":" in args.host else args.host
    print(f"LINCHPIN UI: http://{host}:{args.port}/ui", file=sys.stderr)
    uvicorn.run("linchpin.api.app:app", host=args.host, port=args.port, log_level="warning")
    return 0


def _positive(v: str) -> int:
    n = int(v)
    if n < 1:
        raise argparse.ArgumentTypeError("must be >= 1")
    return n


EXAMPLES = {
    "ingest": "linchpin ingest --replace --match-cpe benchmarks/results/lab/scan-lp-dmz.xml "
              "benchmarks/results/lab/scan-lp-core.xml benchmarks/results/lab/topology.yaml",
    "scenario": "linchpin scenario scenarios/composite_lab.yaml --data-dir ../../datasets/linchpin",
    "synth": "linchpin synth --family ad --hosts 30 --seed 1 --out data/ad.json",
    "intel-build": "linchpin intel-build --data-dir ../../datasets/linchpin",
    "build": "linchpin build",
    "paths": "linchpin paths --k 5 --explain",
    "fix": "linchpin fix --budget 3",
    "cuts": "linchpin cuts --weighted",
    "whatif": "linchpin whatif --remove jump-01",
    "node": "linchpin node host:jump-01",
    "export": "linchpin export --format graphml --out graph.graphml",
    "neo4j-push": "NEO4J_PASSWORD=... linchpin neo4j-push --graph-name lab",
    "serve": "linchpin serve --scenario scenarios/composite_lab.yaml --data-dir ../../datasets/linchpin",
}


def build_parser() -> argparse.ArgumentParser:
    """The argparse parser for every ``linchpin`` command (also renders docs/reference/cli.md)."""
    ap = argparse.ArgumentParser(
        prog="linchpin",
        description="Read-only attack-path reasoning: rank attack paths and the fixes that cut them, from "
                    "already-collected exports or synthetic data. Sends no packets.",
        epilog="Typical flow: linchpin ingest <exports...> -> linchpin fix --budget 3 -> "
               "linchpin whatif --remove <node>. Output is JSON on stdout.")
    ap.add_argument("--version", action="version", version=f"linchpin {__version__}")
    ap.add_argument("--state", default=os.environ.get("LINCHPIN_STATE", ".linchpin/findings.json"),
                    help="findings state file (env LINCHPIN_STATE; default %(default)s)")
    ap.add_argument("--config", default=os.environ.get("LINCHPIN_CONFIG", "config.yaml"),
                    help="weights / entry points / crown jewels YAML (env LINCHPIN_CONFIG; default %(default)s)")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="command")

    def add(name: str, help: str) -> argparse.ArgumentParser:
        """A sub-command whose --help repeats its one-line summary and shows an example."""
        example = EXAMPLES.get(name)
        return sub.add_parser(name, help=help, description=help[0].upper() + help[1:] + ".",
                              epilog=f"example: {example}" if example else None)

    # -- load data
    s = add("ingest", help="parse exports (nmap/OpenVAS/Nessus XML, SharpHound JSON, inventory "
                                      "YAML, native JSON) into the state file")
    s.add_argument("paths", nargs="+", help="files or directories (directories are scanned one level deep)")
    s.add_argument("--replace", action="store_true", help="discard previously ingested findings")
    s.add_argument("--intel", help="CVE intel cache from `intel-build`, to fill in CVSS / EPSS / KEV")
    s.add_argument("--match-cpe", action="store_true",
                   help="map detected service versions (e.g. nmap -sV) to CVEs with the packaged offline NVD "
                        "version-range index")
    s.set_defaults(fn=cmd_ingest)
    s = add("scenario", help="load a scenario YAML (exports + topology overlay + intel) as the state")
    s.add_argument("path", help="scenario YAML, e.g. scenarios/composite_lab.yaml")
    s.add_argument("--data-dir", help="base directory of the exports it lists (default: the YAML's folder)")
    s.add_argument("--no-intel", action="store_true", help="skip NVD / EPSS / KEV enrichment")
    s.set_defaults(fn=cmd_scenario)
    s = add("synth", help="write a synthetic enterprise (findings JSON + ground truth)")
    s.add_argument("--family", choices=["single", "multi", "none", "ad", "legacy"], default="single",
                   help="topology family; all but `legacy` plant real CVEs from the packaged NVD/EPSS/KEV pool "
                        "(`legacy` uses placeholder CVE-2099-* ids) (default %(default)s)")
    s.add_argument("--hosts", type=_positive, default=20, help="number of hosts (default %(default)s)")
    s.add_argument("--seed", type=int, default=0, help="random seed (default %(default)s)")
    s.add_argument("--out", default="data/synth.json", help="output file (default %(default)s)")
    s.set_defaults(fn=cmd_synth)
    s = add("intel-build", help="build the NVD / EPSS / KEV lookup cache from downloaded feeds")
    s.add_argument("--data-dir", default="../../datasets/linchpin",
                   help="folder written by scripts/download_data.py (default %(default)s)")
    s.add_argument("--out", help="cache path (default <data-dir>/derived/cve_intel.csv.gz)")
    s.set_defaults(fn=cmd_intel_build)

    # -- analyse
    add("build", help="build the attack graph and print its size").set_defaults(fn=cmd_build)
    s = add("paths", help="k cheapest entry -> crown-jewel attack paths")
    s.add_argument("--k", type=_positive, default=10, help="number of paths (default %(default)s)")
    s.add_argument("--explain", action="store_true", help="plain-English hop list instead of JSON")
    s.set_defaults(fn=cmd_paths)
    s = add("fix", help="ordered remediation plan with rationale and evidence paths")
    s.add_argument("--budget", type=_positive, default=5, help="maximum number of fixes (default %(default)s)")
    s.set_defaults(fn=cmd_fix)
    s = add("cuts", help="exact minimum remediation cut and single-node chokepoints")
    s.add_argument("--weighted", action="store_true", help="also the minimum-effort cut (config fix_cost)")
    s.set_defaults(fn=cmd_cuts)
    s = add("whatif", help="path statistics with some nodes removed (nothing is persisted)")
    s.add_argument("--remove", nargs="+", required=True, help="node ids; bare names mean host:<name>")
    s.set_defaults(fn=cmd_whatif)
    s = add("node", help="one node with its inbound / outbound attack edges")
    s.add_argument("id", help="node id, e.g. host:jump-01 or cred:svc_backup")
    s.set_defaults(fn=cmd_node)

    # -- export / serve
    s = add("export", help="export the attack graph (Neo4j .cypher script or GraphML)")
    s.add_argument("--format", choices=["cypher", "graphml"], default="cypher", help="default %(default)s")
    s.add_argument("--out", required=True, help="output file")
    s.add_argument("--graph-name", default="default", help="graph tag on every node (default %(default)s)")
    s.set_defaults(fn=cmd_export)
    s = add("neo4j-push", help="mirror the attack graph into Neo4j (password from NEO4J_PASSWORD)")
    s.add_argument("--graph-name", default="default", help="graph tag on every node (default %(default)s)")
    s.set_defaults(fn=cmd_neo4j_push)
    s = add("serve", help="run the API + web UI (localhost only by default; needs the [api] extra)")
    s.add_argument("--host", default="127.0.0.1", help="bind address (default %(default)s)")
    s.add_argument("--port", type=_positive, default=8000, help="port (default %(default)s)")
    s.add_argument("--scenario", help="scenario YAML to preload (else a synthetic demo)")
    s.add_argument("--data-dir", help="base directory for the scenario's exports")
    s.set_defaults(fn=cmd_serve)
    return ap


def main(argv: list[str] | None = None) -> int:
    """CLI entry point; returns the process exit code."""
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
