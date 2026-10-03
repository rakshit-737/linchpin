"""Runtime vs graph size: build + rank (k=10) + optimise (budget 5, k=100), median of repeated runs.

    python benchmarks/scale.py --out benchmarks/results            # sizes 20..300 hosts, 3 runs each

``optimise_s`` already includes the exact minimum cut that ``recommend`` computes; ``mincut_s``
times one standalone min cut for reference and is not added to ``total_s``. The CPU and Python
version are recorded in scale.json; timings are medians of ``--reps`` runs on an idle machine.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from linchpin.engine.cuts import min_remediation_cut
from linchpin.engine.optimizer import recommend
from linchpin.engine.paths import rank_paths
from linchpin.graph.store import GraphStore
from linchpin.runinfo import run_provenance
from linchpin.synth.topologies import generate_family


def cpu_name() -> str:
    """Marketing name of the CPU when the OS exposes it, else platform.processor()."""
    try:
        if sys.platform == "win32":
            import winreg
            key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
            return str(winreg.QueryValueEx(key, "ProcessorNameString")[0]).strip()
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.startswith("model name"):
                return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor()


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


def median_of(family: str, n: int, reps: int) -> dict:
    runs = [one(family, n) for _ in range(reps)]
    out = dict(runs[0])
    for k in ("build_s", "rank_s", "optimise_s", "mincut_s", "total_s"):
        out[k] = round(statistics.median(r[k] for r in runs), 4)
    out["total_s_runs"] = [round(r["total_s"], 4) for r in runs]
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--sizes", default="20,50,100,150,200,300")
    ap.add_argument("--families", default="single,ad")
    ap.add_argument("--reps", type=int, default=3)
    ap.add_argument("--out", default="benchmarks/results")
    a = ap.parse_args(argv)
    rows = [median_of(fam, int(n), a.reps) for fam in a.families.split(",") for n in a.sizes.split(",")]
    for r in rows:
        print(f"{r['family']:7s} hosts={r['hosts']:4d} nodes={r['nodes']:5d} edges={r['edges']:6d} "
              f"build={r['build_s']:.2f}s rank={r['rank_s']:.2f}s opt={r['optimise_s']:.2f}s cut={r['mincut_s']:.2f}s "
              f"total={r['total_s']:.2f}s")
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    meta = {"cpu": cpu_name(), "cpus": os.cpu_count(), "python": platform.python_version(), "os": platform.platform(),
            "reps": a.reps, "statistic": "median", "code": run_provenance(),
            "command": "python benchmarks/scale.py " + " ".join(argv or sys.argv[1:])}
    (out / "scale.json").write_text(json.dumps({"meta": meta, "rows": rows}, indent=2), encoding="utf-8")
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(6, 3.6))
        for fam, c in zip(a.families.split(","), ["#1f5fbf", "#d9822b", "#5aa469", "#9b59b6"], strict=False):
            rs = [r for r in rows if r["family"] == fam]
            ax.plot([r["nodes"] for r in rs], [r["total_s"] for r in rs], "o-", color=c, label=fam)
        ax.axhline(5, ls="--", color="#999", lw=1)
        ax.text(ax.get_xlim()[0], 5.1, "spec target: 5 s", fontsize=8, color="#666")
        ax.set_xlabel("attack-graph nodes")
        ax.set_ylabel(f"build + rank + optimise, s (median of {a.reps})")
        ax.set_title(f"Runtime vs graph size ({meta['cpu']})", fontsize=9)
        ax.legend(frameon=False, fontsize=8)
        ax.spines[["top", "right"]].set_visible(False)
        fig.tight_layout()
        fig.savefig(out / "scale.png", dpi=110)
        plt.close(fig)
    except ImportError:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
