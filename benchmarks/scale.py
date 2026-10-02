"""Runtime vs graph size: build + rank (k=10) + optimise (budget 5, k=100) + exact min cut.

    python benchmarks/scale.py --out benchmarks/results
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from linchpin.engine.cuts import min_remediation_cut
from linchpin.engine.optimizer import recommend
from linchpin.engine.paths import rank_paths
from linchpin.graph.store import GraphStore
from linchpin.synth.topologies import generate_family


def one(family: str, n: int, seed: int = 0) -> dict:
    f, _ = generate_family(family, n, seed)
    s = GraphStore()
    s.upsert_findings(f)
    t = time.perf_counter()
    bs = s.build_attack_graph()
    t_build = time.perf_counter() - t
    t = time.perf_counter()
    rank_paths(s, k=10)
    t_rank = time.perf_counter() - t
    t = time.perf_counter()
    recommend(s, budget=5, k=100)
    t_opt = time.perf_counter() - t
    t = time.perf_counter()
    min_remediation_cut(s)
    t_cut = time.perf_counter() - t
    return {"family": family, "hosts": n, "nodes": bs.nodes, "edges": bs.edges, "build_s": t_build,
            "rank_s": t_rank, "optimise_s": t_opt, "mincut_s": t_cut, "total_s": t_build + t_rank + t_opt}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", default="20,50,100,150,200")
    ap.add_argument("--families", default="single,ad")
    ap.add_argument("--out", default="benchmarks/results")
    a = ap.parse_args(argv)
    rows = [one(fam, int(n)) for fam in a.families.split(",") for n in a.sizes.split(",")]
    for r in rows:
        print(f"{r['family']:7s} hosts={r['hosts']:4d} nodes={r['nodes']:5d} edges={r['edges']:6d} "
              f"build={r['build_s']:.2f}s rank={r['rank_s']:.2f}s opt={r['optimise_s']:.2f}s cut={r['mincut_s']:.2f}s")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    (out / "scale.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(6, 3.6))
        for fam, c in zip(a.families.split(","), ["#1f5fbf", "#d9822b", "#5aa469", "#9b59b6"], strict=False):
            rs = [r for r in rows if r["family"] == fam]
            ax.plot([r["nodes"] for r in rs], [r["total_s"] for r in rs], "o-", color=c, label=fam)
        ax.axhline(5, ls="--", color="#999", lw=1)
        ax.text(ax.get_xlim()[0], 5.1, "5 s target", fontsize=8, color="#666")
        ax.set_xlabel("attack-graph nodes")
        ax.set_ylabel("build + rank + optimise (s)")
        ax.spines[["top", "right"]].set_visible(False)
        ax.legend(frameon=False)
        fig.tight_layout()
        fig.savefig(out / "scale.png", dpi=110)
    except ImportError:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
