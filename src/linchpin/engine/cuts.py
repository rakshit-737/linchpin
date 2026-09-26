"""Exact graph-cut oracles over the attack graph.

* :func:`chokepoints` -- every remediable node that, removed alone, disconnects *all*
  entrypoints from *all* crown jewels (dominators of a virtual sink, O(E alpha(E))).
* :func:`min_remediation_cut` -- the minimum number (or, weighted, total effort) of remediable nodes whose removal
  disconnects everything (vertex-split max-flow / min-cut). This is the optimum the greedy
  optimizer approximates, used by the benchmark to report an optimality gap.

Only *remediable* nodes (Vuln, Credential, non-endpoint Host -- see optimizer.candidates) may
be cut; structural nodes (services, privileges, the internet) get infinite capacity.
"""
from __future__ import annotations

import networkx as nx

_S, _T = "__cut_src__", "__cut_snk__"


def _with_terminals(store, exclude=()) -> nx.DiGraph | None:
    g = store.g.copy()
    g.remove_nodes_from([n for n in exclude if n in g])
    srcs = [s for s in store.entrypoints() if s in g]
    dsts = [t for t in store.crown_jewels() if t in g]
    if not srcs or not dsts:
        return None
    g.add_edges_from((_S, s) for s in srcs)
    g.add_edges_from((t, _T) for t in dsts)
    if not nx.has_path(g, _S, _T):
        return None
    return g


def chokepoints(store, candidates: list[str] | None = None) -> list[str]:
    """Remediable nodes lying on every entry -> crown-jewel route (single points of failure)."""
    from linchpin.engine.optimizer import candidates as _cands
    g = _with_terminals(store)
    if g is None:
        return []
    cand = set(candidates if candidates is not None else _cands(store))
    idom = nx.immediate_dominators(g, _S)
    out, n = [], _T
    while n != _S:
        n = idom[n]
        if n in cand:
            out.append(n)
    return out[::-1]  # ordered entry -> crown jewel


def fix_cost(store, node_id: str) -> float:
    """Remediation effort of one candidate node (config ``fix_cost`` by label, default 1)."""
    a = store.g.nodes[node_id]
    return float(a.get("fix_cost") or store.cfg.fix_cost.get(a.get("label"), 1.0))


def min_remediation_cut(store, candidates: list[str] | None = None, weighted: bool = False) -> list[str] | None:
    """Minimum set of remediable nodes disconnecting all crown jewels.

    ``weighted=False`` minimises the number of fixes; ``weighted=True`` minimises total
    remediation effort (:func:`fix_cost`, e.g. a segmentation rule costs 3 patches).
    Returns [] if nothing is reachable already, or None if no finite cut exists (e.g. an
    entrypoint service leads straight to a crown jewel with nothing remediable in between).
    """
    from linchpin.engine.optimizer import candidates as _cands
    g = _with_terminals(store)
    if g is None:
        return []
    cand = set(candidates if candidates is not None else _cands(store))
    cap = {n: (fix_cost(store, n) if weighted else 1.0) for n in cand}
    big = float(sum(cap.values()) + 1)
    h = nx.DiGraph()
    for n in g.nodes:
        h.add_edge((n, "i"), (n, "o"), capacity=cap[n] if n in cand else big)
    for u, v in g.edges:
        h.add_edge((u, "o"), (v, "i"), capacity=big)
    value, (reach, _) = nx.minimum_cut(h, (_S, "o"), (_T, "i"))
    if value >= big:
        return None
    return sorted(n for n in cand if (n, "i") in reach and (n, "o") not in reach)
