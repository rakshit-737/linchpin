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
    store = GraphStore(load_config(args.config))
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
    files: list[str] = []
    for p in args.paths:
        if os.path.isdir(p):
            files += sorted(str(x) for x in Path(p).iterdir() if x.suffix in (".json", ".xml"))
        else:
            files.append(p)
    existing = {}
    st = _state(args)
    if st.exists() and not args.replace:
        existing = {x["finding_id"]: x for x in json.loads(st.read_text())}
    n = 0
    for f in files:
        for finding in parse_any(f):
            existing[finding.finding_id] = finding.model_dump()
            n += 1
    st.parent.mkdir(parents=True, exist_ok=True)
    st.write_text(json.dumps(list(existing.values())))
    _emit({"files": files, "accepted": n, "total_findings": len(existing)})
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
    s = sub.add_parser("ingest", help="ingest exported findings (JSON / nmap XML) from files or dirs")
    s.add_argument("paths", nargs="+")
    s.add_argument("--replace", action="store_true", help="discard previously ingested findings")
    s.set_defaults(fn=cmd_ingest)
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
