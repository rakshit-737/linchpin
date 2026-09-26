"""Remediation-ordering benchmark over four topology families with real CVE parameters.

    python benchmarks/run_benchmark.py --seeds 50 --budget 3 --out benchmarks/results

Writes rows.csv, summary.json, summary.md and figures (PNG) to --out.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from linchpin.benchmark import STRATEGIES, run_one, summarise  # noqa: E402
from linchpin.synth.topologies import FAMILIES  # noqa: E402

LABEL = {"linchpin": "LINCHPIN (exact+greedy)", "greedy": "LINCHPIN greedy only", "cvss": "CVSS-first",
         "epss": "EPSS-first", "kev_epss": "KEV then EPSS", "betweenness": "Betweenness", "random": "Random"}


def _gain(x, ci=None) -> str:
    if x is None:
        return "n/a (all disconnected)"
    return f"{x:+.3f}" + (f" [{ci[0]:+.3f}, {ci[1]:+.3f}]" if ci else "")


def _rate(a) -> str:
    lo, hi = a.get("disconnect_ci95") or (None, None)
    return f"{a['disconnect_rate']:.0%}" + (f" [{lo:.0%}, {hi:.0%}]" if lo is not None else "")


def md_table(summ: dict, budget: int) -> str:
    lines = [f"Budget = {budget} fixes per topology. Disconnect = no crown jewel reachable afterwards. "
             "Residual = attack paths still enumerated (capped at k=100) as a fraction of before (mean ± s.e.). "
             "Brackets: 95% Wilson interval (rates) and 95% seeded bootstrap interval (cost gain).", ""]
    for fam, agg in summ.items():
        mc = agg["mean_min_cut"]
        lines.append(f"**{fam}** — n={agg['n']}, mean graph size {agg['mean_nodes']:.0f} nodes, "
                     f"topologies with a single-node chokepoint {agg['with_chokepoint']:.0%}, "
                     f"mean exact min cut {mc:.2f} fixes" if mc is not None else f"**{fam}**")
        lines.append("")
        lines.append("| strategy | disconnect rate | residual paths | attacker cost gain (still connected) | ms |")
        lines.append("| --- | ---: | ---: | ---: | ---: |")
        for s in STRATEGIES:
            a = agg[s]
            lines.append(f"| {LABEL[s]} | {_rate(a)} | {a['residual_frac']:.2f} ± "
                         f"{a['residual_frac_se']:.2f} | {_gain(a['cost_gain_connected'], a.get('cost_gain_ci95'))} "
                         f"| {a['mean_ms']:.0f} |")
        extra = []
        if agg.get("greedy_mean_ratio") is not None:
            extra.append(f"greedy fixes-to-disconnect / exact min cut = {agg['greedy_mean_ratio']:.2f} "
                         f"(optimal in {agg['greedy_optimal_rate']:.0%})")
        if agg.get("top1_planted_rate") is not None:
            extra.append(f"top-1 = planted linchpin in {agg['top1_planted_rate']:.0%}")
        if agg["with_chokepoint"]:
            extra.append(f"top-1 is a true chokepoint in {agg['top1_chokepoint_rate']:.0%} of chokepoint topologies")
        if extra:
            lines += ["", "; ".join(extra) + "."]
        lines.append("")
    return "\n".join(lines)


def plot(summ: dict, out: Path) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return
    fams = list(summ)
    fig, axes = plt.subplots(1, 2, figsize=(11, 3.8))
    w = 0.8 / len(STRATEGIES)
    colors = ["#1f5fbf", "#6f9be0", "#d9822b", "#e0b04a", "#9b59b6", "#5aa469", "#999999"]
    for i, s in enumerate(STRATEGIES):
        xs = [j + (i - len(STRATEGIES) / 2) * w + w / 2 for j in range(len(fams))]
        axes[0].bar(xs, [summ[f][s]["disconnect_rate"] for f in fams], w, label=LABEL[s], color=colors[i])
        axes[1].bar(xs, [summ[f][s]["residual_frac"] for f in fams], w, color=colors[i],
                    yerr=[summ[f][s]["residual_frac_se"] for f in fams], capsize=2)
    for ax, t in zip(axes, ["Crown jewels disconnected (higher is better)", "Residual attack paths (lower is better)"]):
        ax.set_xticks(range(len(fams)), fams)
        ax.set_title(t, fontsize=10)
        ax.set_ylim(0, 1.05)
        ax.spines[["top", "right"]].set_visible(False)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, fontsize=8, frameon=False, loc="lower center", ncol=len(STRATEGIES))
    fig.tight_layout(rect=(0, 0.08, 1, 1))
    fig.savefig(out / "strategies.png", dpi=110)
    plt.close(fig)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=50)
    ap.add_argument("--budget", type=int, default=3)
    ap.add_argument("--k", type=int, default=100)
    ap.add_argument("--families", default=",".join(FAMILIES))
    ap.add_argument("--out", default="benchmarks/results")
    ap.add_argument("--replot", action="store_true", help="only redraw figures from summary.json")
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    if a.replot:
        plot(json.loads((out / "summary.json").read_text(encoding="utf-8"))["families"], out)
        return 0
    rows = []
    t0 = time.time()
    for fam in a.families.split(","):
        for seed in range(a.seeds):
            n = 12 + (seed * 7) % 49  # 12..60 hosts
            rows.append(run_one(fam, seed, n, a.budget, a.k))
        print(f"{fam}: done ({time.time() - t0:.0f}s)", flush=True)
    with (out / "rows.csv").open("w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    summ = summarise(rows)
    meta = {"seeds_per_family": a.seeds, "budget": a.budget, "k_cap": a.k, "hosts": "12..60",
            "runtime_s": round(time.time() - t0, 1)}
    (out / "summary.json").write_text(json.dumps({"meta": meta, "families": summ}, indent=2,
                                                 default=str), encoding="utf-8")
    (out / "summary.md").write_text(md_table(summ, a.budget) + "\n", encoding="utf-8")
    plot(summ, out)
    print(md_table(summ, a.budget))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
