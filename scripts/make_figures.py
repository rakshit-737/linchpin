"""Figures for the docs' "How it works" page (python scripts/make_figures.py).

1. how/attack_graph.png -- a small seeded `single` topology as LINCHPIN builds it: hosts,
   services, vulns, privileges, credentials and the crown jewel, with the cheapest attack path
   and the exact minimum cut highlighted.
2. how/cost_curves.png -- on a `none` topology (no small cut): the attacker's cheapest-path cost
   after 0..5 fixes chosen by LINCHPIN, the exact interdiction MILP and CVSS-first.
3. copies benchmarks/results/{strategies,scale}.png to docs/img/results/ for the docs site.

Everything is seeded; regenerate after changing the engine.
"""
from __future__ import annotations

import itertools
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import networkx as nx

from linchpin.benchmark import order
from linchpin.engine.cuts import min_remediation_cut
from linchpin.engine.interdiction import cheapest_path
from linchpin.graph.store import GraphStore
from linchpin.synth.topologies import generate_family

OUT = Path(__file__).resolve().parents[1] / "docs" / "img" / "how"
COLORS = {"Internet": "#6b7280", "Host": "#1f5fbf", "Service": "#94a3b8", "Vuln": "#d97706", "Credential": "#7c3aed",
          "Privilege": "#0891b2", "DataStore": "#15803d", "Ace": "#be185d"}
LAYER = {"Internet": 0, "Service": 1, "Vuln": 2, "Privilege": 3, "Host": 4, "Credential": 5, "DataStore": 6}


def store_for(family: str, n: int, seed: int) -> GraphStore:
    f, _ = generate_family(family, n, seed)
    s = GraphStore()
    s.upsert_findings(f)
    s.build_attack_graph()
    return s


def attack_graph(path: Path) -> None:
    s = store_for("single", 8, 0)
    keep = set(s.entrypoints()).union(*(nx.descendants(s.g, e) for e in s.entrypoints()))
    g = s.g.subgraph(n for n in s.g if n in keep).copy()
    best = s.k_shortest_paths(k=1)[0].nodes
    cut = set(min_remediation_cut(s) or [])
    # left-to-right by "stage" of the node along the cheapest attack path, then by type
    depth = nx.single_source_shortest_path_length(g, "internet")
    pos = {}
    by_layer: dict[int, list[str]] = {}
    for n in g:
        by_layer.setdefault(depth.get(n, 0), []).append(n)
    for x, nodes in by_layer.items():
        nodes.sort(key=lambda n: (LAYER.get(g.nodes[n].get("label"), 9), n))
        for i, n in enumerate(nodes):
            pos[n] = (x, -(i - (len(nodes) - 1) / 2))
    fig, ax = plt.subplots(figsize=(12, 5.2))
    on_path = set(itertools.pairwise(best))
    nx.draw_networkx_edges(g, pos, ax=ax, edge_color=["#1f5fbf" if e in on_path else "#d6d9de" for e in g.edges],
                           width=[2.2 if e in on_path else 0.6 for e in g.edges], arrowsize=7, node_size=120)
    nx.draw_networkx_nodes(g, pos, ax=ax, node_size=[260 if n in cut else 110 for n in g],
                           node_color=[COLORS.get(g.nodes[n].get("label"), "#999") for n in g],
                           edgecolors=["#c2410c" if n in cut else "white" for n in g],
                           linewidths=[2.5 if n in cut else 0.5 for n in g])
    labels = {n: n.split(":", 1)[-1].split("@")[0][:18] for n in g
              if g.nodes[n].get("label") in ("Host", "DataStore", "Credential", "Internet") or n in cut}
    nx.draw_networkx_labels(g, pos, labels, ax=ax, font_size=7, verticalalignment="bottom")
    handles = [plt.Line2D([], [], marker="o", ls="", color=c, label=lbl) for lbl, c in COLORS.items()
               if lbl != "Ace"]
    handles += [plt.Line2D([], [], color="#1f5fbf", lw=2.2, label="cheapest attack path"),
                plt.Line2D([], [], marker="o", ls="", mfc="white", mec="#c2410c", mew=2.5,
                           label="exact minimum cut (1 fix)")]
    ax.legend(handles=handles, fontsize=7.5, frameon=False, loc="lower center", ncol=5, bbox_to_anchor=(0.5, -0.16))
    ax.set_title("A seeded `single` topology as an attack graph (edges point the way the attacker moves)", fontsize=10)
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(path, dpi=110)
    plt.close(fig)


def cost_curves(path: Path) -> None:
    s = store_for("none", 20, 3)
    base, _ = cheapest_path(s)
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    for strat, label, color in (("milp_interdiction", "exact interdiction MILP (optimum)", "#2a7f62"),
                                ("linchpin", "LINCHPIN (greedy set cover here)", "#1f5fbf"),
                                ("cvss", "CVSS-first", "#d9822b")):
        ys = [base]
        for b in range(1, 6):
            rem = order(s, strat, b, k=100)
            ys.append(cheapest_path(s, rem)[0])
        ax.plot(range(0, 6), ys, "o-", color=color, label=label, lw=1.6, ms=4)
    ax.set_xlabel("fixes applied")
    ax.set_ylabel("attacker's cheapest path cost")
    mc = len(min_remediation_cut(s) or [])
    ax.set_title(f"`none` topology (exact min cut {mc} fixes): raising the attacker's cost when no cut fits",
                 fontsize=9)
    ax.legend(frameon=False, fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(path, dpi=110)
    plt.close(fig)


def sync_result_figures() -> None:
    """The docs site can only show images under docs/: copy the benchmark figures there."""
    import shutil
    root = OUT.parents[2]
    for name in ("strategies.png", "scale.png"):
        src = root / "benchmarks" / "results" / name
        if src.exists():
            shutil.copyfile(src, root / "docs" / "img" / "results" / name)


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    attack_graph(OUT / "attack_graph.png")
    cost_curves(OUT / "cost_curves.png")
    sync_result_figures()
    for p in sorted(OUT.glob("*.png")):
        print(f"wrote {p} ({p.stat().st_size / 1e3:.0f} kB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
