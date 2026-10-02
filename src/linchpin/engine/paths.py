"""M4: path ranking and per-node criticality."""
from __future__ import annotations

from collections import Counter

import networkx as nx

from linchpin.config import Config
from linchpin.models import AttackPath


def rank_paths(store, cfg: Config | None = None, k: int | None = None) -> list[AttackPath]:
    """The k cheapest entry-to-crown-jewel paths, ordered by (cost, length, path id)."""
    cfg = cfg or store.cfg
    paths = store.k_shortest_paths(k=k or cfg.k_shortest)
    return sorted(paths, key=lambda p: (p.total_cost, len(p.nodes), p.path_id))


def node_criticality(paths: list[AttackPath]) -> dict[str, float]:
    """0.7 * fraction-of-paths-through-node + 0.3 * normalised betweenness on the path subgraph.

    Endpoints (entry and crown jewel) are excluded: they are trivially on every path.
    """
    if not paths:
        return {}
    counts: Counter[str] = Counter()
    sub = nx.DiGraph()
    for p in paths:
        counts.update(set(p.nodes[1:-1]))
        nx.add_path(sub, p.nodes)
    btw = nx.betweenness_centrality(sub, normalized=True)
    top = max(btw.values()) or 1.0
    crit = {n: 0.7 * c / len(paths) + 0.3 * btw.get(n, 0.0) / top for n, c in counts.items()}
    return dict(sorted(crit.items(), key=lambda kv: (-kv[1], kv[0])))
