"""Remediation-ordering benchmark over four topology families with real CVE parameters.

    python benchmarks/run_benchmark.py --seeds 50 --budget 3 --workers 6 --out benchmarks/results

Writes rows.csv, summary.json, summary.md and strategies.png to --out. Topologies are
independent, so they run in a process pool; results are identical for any worker count
(per-strategy milliseconds are wall-clock under that load).
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import platform
import sys
import time
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from linchpin.benchmark import LABEL, MIN_N_FOR_CI, STRATEGIES, format_p, hosts_for_seed, run_one, summarise
from linchpin.runinfo import run_provenance
from linchpin.synth.topologies import FAMILIES, pool_provenance

# strategies shown in the headline tables / figure (the full set is in summary.json)
SHOWN = STRATEGIES


def _gain(a: dict) -> str:
    x, n, ci = a["cost_gain_connected"], a["cost_gain_n"], a.get("cost_gain_ci95")
    if x is None:
        return "n/a (all disconnected)"
    txt = f"{x:+.3f}"
    if ci:
        txt += f" [{ci[0]:+.3f}, {ci[1]:+.3f}]"
    return txt + f" (n={n}{', no CI: n<' + str(MIN_N_FOR_CI) if not ci else ''})"


def _rate(a: dict) -> str:
    lo, hi = a.get("disconnect_ci95") or (None, None)
    return f"{a['disconnect_rate']:.0%}" + (f" [{lo:.0%}, {hi:.0%}]" if lo is not None else "")


def _p(x: float) -> str:
    return format_p(x)


def _diff(d: dict | None) -> str:
    if not d:
        return "-"
    ci = d.get("ci95")
    return (f"{d['mean_diff']:+.3f}" + (f" [{ci[0]:+.3f}, {ci[1]:+.3f}]" if ci else "")
            + f"; {d['a_larger']} / {d['b_larger']} / {d['ties']}; p {_eq(format_p(d['p_sign']))}")


def _eq(p: str) -> str:
    return p if p.startswith("<") else f"= {p}"


def provenance_line(meta: dict) -> str:
    """Which code and run produced the table."""
    code = meta.get("code") or {}
    if code.get("github_run_id"):
        return (f"Produced by CI run [{code['github_run_id']}]({code['github_run_url']}) at commit "
                f"{(code.get('github_sha') or '')[:12]} ({meta.get('workers')} workers, {meta.get('runtime_s')} s).")
    if code.get("git_commit"):
        return (f"Produced at commit {code['git_commit'][:12]}"
                + (" with uncommitted code changes" if code.get("git_dirty_code") else "") + ".")
    return "Produced before run provenance was recorded (v1.1.0 or earlier)."


def md_table(summ: dict, budget: int, k: int) -> str:
    lines = [f"Budget = {budget} fixes per topology. Disconnect = no crown jewel reachable afterwards (95% Wilson "
             f"interval). Residual = attack paths still enumerated (capped at k={k}) as a fraction of before "
             "(mean ± s.e.). Cost gain = rise of the attacker's cheapest-path cost on topologies that stay "
             f"connected (95% seeded bootstrap interval; n = such topologies; no interval when n < {MIN_N_FOR_CI}). "
             "p = exact McNemar test of the disconnect outcome against LINCHPIN on the same topologies.", ""]
    for fam, agg in summ.items():
        if fam in ("pooled", "residual_reduction_vs_cvss"):
            continue
        mc = agg["mean_min_cut"]
        lo_h, hi_h = agg["hosts_range"]
        lo_n, hi_n = agg["nodes_range"]
        lines.append(f"**{fam}**: n={agg['n']}, {lo_h}-{hi_h} hosts ({lo_n}-{hi_n} nodes, mean "
                     f"{agg['mean_nodes']:.0f}), single-node chokepoint in {agg['with_chokepoint']:.0%}, "
                     + (f"mean exact min cut {mc:.2f} fixes" if mc is not None else "no finite cut"))
        lines += ["", "| strategy | disconnect rate | p vs LINCHPIN | residual paths | attacker cost gain "
                      "(still connected) | share of optimal gain | ms |",
                  "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
        for s in SHOWN:
            a = agg[s]
            p = a.get("vs_linchpin", {}).get("p_mcnemar")
            share = a.get("share_of_optimal_gain")
            sci = a.get("share_of_optimal_gain_ci95")
            share_txt = "-" if share is None else (f"{share:.2f}" + (f" [{sci[0]:.2f}, {sci[1]:.2f}]" if sci else ""))
            lines.append(f"| {LABEL[s]} | {_rate(a)} | {'-' if p is None else _p(p)} | {a['residual_frac']:.2f} ± "
                         f"{a['residual_frac_se']:.2f} | {_gain(a)} | {share_txt} | {a['mean_ms']:.0f} |")
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
        paired = [(s, agg[s].get("gain_vs_linchpin")) for s in SHOWN if agg[s].get("gain_vs_linchpin")]
        if fam == "none" and paired:
            lines += ["", "Paired on the same topologies (none disconnects): LINCHPIN's cost gain minus the "
                          "strategy's, mean [95% bootstrap interval]; topologies where LINCHPIN's gain is larger / "
                          "smaller / equal; exact sign test.", "",
                      "| strategy | LINCHPIN gain - strategy gain | larger / smaller / equal; p |",
                      "| --- | ---: | ---: |"]
            for s, d in paired:
                head, _, tail = _diff(d).partition("; ")
                lines.append(f"| {LABEL[s]} | {head} | {tail} |")
        lines.append("")
    if "pooled" in summ:
        pl = summ["pooled"]
        lines += [f"**Pooled over {', '.join(pl['families'])}** (n={pl['n']}; the families where a {budget}-fix "
                  "plan can disconnect):", "",
                  "| strategy | disconnect rate | LINCHPIN-only / strategy-only | p | strategy-only / random-only "
                  "| p vs random |", "| --- | ---: | ---: | ---: | ---: | ---: |"]
        for s in SHOWN:
            a = pl[s]
            vs, vr = a.get("vs_linchpin"), a.get("vs_random")
            pair = "-" if not vs else f"{vs['only_linchpin']} / {vs['only_' + s]}"
            rpair = "-" if not vr else f"{vr['only_' + s]} / {vr['only_random']}"
            lines.append(f"| {LABEL[s]} | {_rate(a)} | {pair} | {'-' if not vs else _p(vs['p_mcnemar'])} | {rpair} "
                         f"| {'-' if not vr else _p(vr['p_mcnemar'])} |")
        lines.append("")
    if "residual_reduction_vs_cvss" in summ:
        r = summ["residual_reduction_vs_cvss"]
        lo, hi = r["ci95"]
        lines += [f"Difference in the share of enumerated attack paths (k-capped) left after 3 fixes, CVSS-first minus "
                  f"LINCHPIN, over all {r['n']} topologies: **{r['mean']:.1%}** [{lo:.1%}, {hi:.1%}] (bootstrap)."]
        per = r.get("per_family") or {}
        if per:
            lines[-1] += " Per family: " + ", ".join(
                f"{f} {v['mean']:.1%} [{v['ci95'][0]:.1%}, {v['ci95'][1]:.1%}]" for f, v in per.items()) + "."
        w = r.get("where_a_cut_fits")
        if w:
            lines[-1] += (f" Over the {w['n']} topologies of {', '.join(w['families'])} (where a 3-fix cut exists): "
                          f"{w['mean']:.1%} [{w['ci95'][0]:.1%}, {w['ci95'][1]:.1%}].")
        if per.get("none", {}).get("mean") == 0:
            lines[-1] += " In none both plans leave the k-capped re-enumeration full, so that family contributes 0."
        lines.append("")
    return "\n".join(lines)


COLORS = {"linchpin": "#1f5fbf", "greedy": "#6f9be0", "milp_interdiction": "#2a7f62",
          "greedy_interdiction": "#7fc8a9", "vuln_only": "#17becf", "cvss": "#d9822b", "cvss_reach": "#f0b97a",
          "epss": "#c0392b",
          "epss_reach": "#e8908a", "kev_epss": "#8e44ad", "kev_epss_reach": "#c39bd3", "betweenness": "#5a5a5a",
          "random": "#b0b0b0"}


def plot(summ: dict, out: Path) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return
    fams = [f for f in summ if f not in ("pooled", "residual_reduction_vs_cvss")]
    fig, axes = plt.subplots(1, 2, figsize=(12, 5.0))
    w = 0.84 / len(SHOWN)
    for i, s in enumerate(SHOWN):
        xs = [j + (i - len(SHOWN) / 2) * w + w / 2 for j in range(len(fams))]
        rates = [summ[f][s]["disconnect_rate"] for f in fams]
        lo = [r - summ[f][s]["disconnect_ci95"][0] for f, r in zip(fams, rates, strict=True)]
        hi = [summ[f][s]["disconnect_ci95"][1] - r for f, r in zip(fams, rates, strict=True)]
        axes[0].bar(xs, rates, w, label=LABEL[s], color=COLORS[s], yerr=[lo, hi], capsize=1.5,
                    error_kw={"elinewidth": 0.7})
        axes[1].bar(xs, [summ[f][s]["residual_frac"] for f in fams], w, color=COLORS[s],
                    yerr=[summ[f][s]["residual_frac_se"] for f in fams], capsize=1.5, error_kw={"elinewidth": 0.7})
    titles = ["Crown jewels cut off with 3 fixes (higher is better)", "Attack paths left (lower is better)"]
    ylabels = ["disconnect rate (95% Wilson CI)", "residual paths / paths before (mean ± s.e.)"]
    for ax, t, yl in zip(axes, titles, ylabels, strict=True):
        ax.set_xticks(range(len(fams)), fams)
        ax.set_title(t, fontsize=10)
        ax.set_ylabel(yl, fontsize=9)
        ax.set_xlabel("topology family (50 seeds each)", fontsize=9)
        ax.set_ylim(0, 1.05)
        ax.spines[["top", "right"]].set_visible(False)
    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, fontsize=8, frameon=False, loc="lower center", ncol=4)
    fig.tight_layout(rect=(0, 0.17, 1, 1))
    fig.savefig(out / "strategies.png", dpi=110)
    plt.close(fig)


def _task(args: tuple) -> dict:
    fam, seed, budget, k = args
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
    ap.add_argument("--replot", action="store_true", help="only redraw the figure and table from summary.json")
    a = ap.parse_args(argv)
    out = Path(a.out)
    out.mkdir(parents=True, exist_ok=True)
    if a.replot:
        doc = json.loads((out / "summary.json").read_text(encoding="utf-8"))
        plot(doc["families"], out)
        (out / "summary.md").write_text(md_table(doc["families"], doc["meta"]["budget"], doc["meta"]["k_cap"])
                                        + provenance_line(doc["meta"]) + "\n", encoding="utf-8")
        return 0
    code = run_provenance()
    tasks = [(fam, seed, a.budget, a.k) for fam in a.families.split(",") for seed in range(a.seeds)]
    t0 = time.time()
    if a.workers > 1:
        with ProcessPoolExecutor(max_workers=a.workers) as ex:
            rows = list(ex.map(_task, tasks, chunksize=1))
    else:
        rows = [_task(t) for t in tasks]
    runtime = round(time.time() - t0, 1)
    with (out / "rows.csv").open("w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    summ = summarise(rows)
    meta = {"seeds_per_family": a.seeds, "budget": a.budget, "k_cap": a.k,
            "hosts": f"{min(r['n_hosts'] for r in rows)}..{max(r['n_hosts'] for r in rows)} "
                     f"({len({r['n_hosts'] for r in rows})} sizes, 12 + seed mod 49)",
            "nodes": f"{min(r['nodes'] for r in rows)}..{max(r['nodes'] for r in rows)}",
            "cve_pool": pool_provenance(), "runtime_s": runtime, "workers": a.workers, "code": code,
            "platform": {"python": platform.python_version(), "machine": platform.machine(),
                         "processor": platform.processor(), "cpus": os.cpu_count()}}
    clean = json.loads(json.dumps({"meta": meta, "families": summ}, default=_clean))
    (out / "summary.json").write_text(json.dumps(clean, indent=2), encoding="utf-8")
    (out / "summary.md").write_text(md_table(summ, a.budget, a.k) + provenance_line(meta) + "\n", encoding="utf-8")
    plot(summ, out)
    print(md_table(summ, a.budget, a.k))
    print(f"runtime {runtime:.0f}s with {a.workers} workers")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
