"""Budgeted shortest-path interdiction: comparison planners from the network-interdiction literature.

LINCHPIN's optimizer cuts *paths* (exact vertex min cut, else greedy set cover). The
interdiction literature instead maximises the attacker's *cheapest* path cost after at most
``budget`` removals, which is the right objective when no plan within budget can disconnect.

* :func:`greedy_interdiction` -- each round, remove the remediable node on the current
  cheapest attack path whose removal raises that cost the most (disconnecting = infinitely
  much). This is the shape of the GREEDY blocking baseline used for Active Directory attack
  graphs by Guo et al. (AAAI 2022, 2023); it is a re-implementation of the idea on LINCHPIN's
  graph and cost model, not a reproduction of their system.
* :func:`exact_interdiction` -- the optimum, from the mixed-integer program of Israeli & Wood,
  "Shortest-path network interdiction", Networks 40(2), 2002 (doi:10.1002/net.10039): the
  inner shortest path is replaced by its LP dual (node potentials), node removal is an
  interdicted split arc with a big-M length, and the MILP is solved with HiGHS through
  :func:`scipy.optimize.milp` (needs the ``[ml]`` extra for scipy).

Both use the same remediable candidates as the optimizer and the same edge costs, so their
plans are scored with exactly the metrics of :mod:`linchpin.benchmark`.
"""
from __future__ import annotations

import math
from collections.abc import Iterable

import networkx as nx


def _relevant(store) -> tuple[set[str], list[str], list[str]]:
    """Nodes on some entry -> crown-jewel route, with the sources and targets inside it."""
    g = store.g
    sources = [s for s in store.entrypoints() if s in g]
    targets = [t for t in store.crown_jewels() if t in g]
    if not sources or not targets:
        return set(), [], []
    fwd = set(sources).union(*(nx.descendants(g, s) for s in sources))
    bwd = set(targets).union(*(nx.ancestors(g, t) for t in targets))
    keep = fwd & bwd
    return keep, [s for s in sources if s in keep], [t for t in targets if t in keep]


def cheapest_path(store, exclude: Iterable[str] = ()) -> tuple[float, list[str]]:
    """Cost and node list of the cheapest entry -> crown-jewel path with ``exclude`` removed.

    Returns ``(inf, [])`` when no crown jewel is reachable.
    """
    banned = set(exclude)
    g = store.g
    sources = [s for s in store.entrypoints() if s in g and s not in banned]
    targets = {t for t in store.crown_jewels() if t in g and t not in banned}
    if not sources or not targets:
        return math.inf, []

    def weight(u: str, v: str, d: dict) -> float | None:
        return None if v in banned else d["cost"]

    dist, paths = nx.multi_source_dijkstra(g, sources, weight=weight)
    best = min((t for t in targets if t in dist), key=lambda t: (dist[t], t), default=None)
    if best is None:
        return math.inf, []
    return dist[best], paths[best]


def greedy_interdiction(store, budget: int, candidates: Iterable[str] | None = None) -> list[str]:
    """Greedy shortest-path interdiction (Guo et al.-style GREEDY): up to ``budget`` node ids."""
    from linchpin.engine.optimizer import candidates as _cands
    cand = set(candidates if candidates is not None else _cands(store))
    removed: list[str] = []
    for _ in range(budget):
        _, path = cheapest_path(store, removed)
        if not path:
            break
        options = [n for n in path if n in cand and n not in removed]
        if not options:
            break
        scored = [(cheapest_path(store, [*removed, n])[0], n) for n in options]
        best_cost = max(c for c, _ in scored)
        removed.append(min(n for c, n in scored if c == best_cost))
    return removed


def exact_interdiction(store, budget: int, candidates: Iterable[str] | None = None,
                       time_limit: float = 60.0) -> dict:
    """Optimal ``budget``-node interdiction of the cheapest attack path (Israeli & Wood MILP).

    Returns:
        ``{"removed": [...], "value": float, "disconnected": bool, "status": str}`` where
        ``value`` is the attacker's cheapest-path cost after the removals (``inf`` when they
        disconnect every crown jewel) and ``status`` is ``optimal`` or ``time_limit``.
    """
    import numpy as np
    from scipy.optimize import Bounds, LinearConstraint, milp
    from scipy.sparse import coo_matrix

    from linchpin.engine.optimizer import candidates as _cands
    keep, sources, targets = _relevant(store)
    if not targets:
        return {"removed": [], "value": math.inf, "disconnected": True, "status": "optimal"}
    g = store.g
    cand = sorted(n for n in (candidates if candidates is not None else _cands(store)) if n in keep)
    order = [n for n in g if n in keep]  # graph insertion order: deterministic
    idx_in, idx_out = {}, {}
    nxt = 2  # 0 = virtual source S, 1 = virtual sink T
    for n in order:
        idx_in[n] = nxt
        idx_out[n] = nxt + 1 if n in cand else nxt
        nxt += 2 if n in cand else 1
    n_pi = nxt
    xcol = {c: n_pi + i for i, c in enumerate(cand)}
    n_var = n_pi + len(cand)
    edges = [(u, v, float(a["cost"])) for u, v, a in g.edges(data=True) if u in keep and v in keep]
    big_m = sum(c for _, _, c in edges) + 1.0

    rows, cols, vals, ub = [], [], [], []

    def row(entries: list[tuple[int, float]], rhs: float) -> None:
        r = len(ub)
        for c, v in entries:
            rows.append(r)
            cols.append(c)
            vals.append(v)
        ub.append(rhs)

    for u, v, c in edges:  # pi[v_in] - pi[u_out] <= cost(u, v)
        row([(idx_in[v], 1.0), (idx_out[u], -1.0)], c)
    for s in sources:  # S -> source, cost 0
        row([(idx_in[s], 1.0), (0, -1.0)], 0.0)
    for t in targets:  # crown jewel -> T, cost 0
        row([(1, 1.0), (idx_out[t], -1.0)], 0.0)
    for c in cand:  # split arc c_in -> c_out costs big_m when c is removed
        row([(idx_out[c], 1.0), (idx_in[c], -1.0), (xcol[c], -big_m)], 0.0)
    a_ub = coo_matrix((vals, (rows, cols)), shape=(len(ub), n_var)).tocsr()
    budget_row = np.zeros(n_var)
    budget_row[n_pi:] = 1.0
    cons = [LinearConstraint(a_ub, -np.inf, np.array(ub)),
            LinearConstraint(budget_row.reshape(1, -1), -np.inf, float(budget))]
    lo = np.zeros(n_var)
    hi = np.full(n_var, big_m * (budget + 1))
    hi[0] = 0.0  # pi[S] = 0
    hi[n_pi:] = 1.0
    integrality = np.zeros(n_var)
    integrality[n_pi:] = 1
    obj = np.zeros(n_var)
    obj[1] = -1.0  # maximise pi[T]
    res = milp(obj, constraints=cons, integrality=integrality, bounds=Bounds(lo, hi),
               options={"time_limit": time_limit, "mip_rel_gap": 1e-9})
    if res.x is None:
        raise RuntimeError(f"interdiction MILP failed: {res.message}")
    removed = [c for c in cand if res.x[xcol[c]] > 0.5]
    value, _ = cheapest_path(store, removed)  # re-evaluate exactly (no big-M rounding)
    return {"removed": removed, "value": value, "disconnected": math.isinf(value),
            "status": "optimal" if res.status == 0 else "time_limit", "milp_objective": float(-res.fun)}
