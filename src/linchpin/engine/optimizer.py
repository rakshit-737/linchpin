"""M5: greedy set-cover remediation optimizer."""
from __future__ import annotations

from linchpin.config import Config
from linchpin.engine.explain import explain_remediation
from linchpin.models import AttackPath, Remediation

CANDIDATE_LABELS = {"Vuln", "Credential", "Host", "Ace"}


def action_for(store, node_id: str) -> str:
    """The remediation verb for a node: patch / upgrade, rotate credential, remove ACE, segment host."""
    a = store.g.nodes[node_id]
    lbl = a.get("label")
    if lbl == "Vuln":
        if a.get("upgrade"):  # matched by product version (intel/cpe.py): the fix is an upgrade
            return f"upgrade {a['upgrade']} on {a['host_id']} ({len(a.get('cves') or [])} known CVEs)"
        if a.get("cve") and len(a.get("cves") or []) <= 1:
            return f"patch {a['cve']} on {a['host_id']}"
        what = a.get("name") or a.get("cve") or node_id
        return f"apply fix for '{what}' on {a['host_id']}"
    if lbl == "Credential":
        return f"rotate credential {a['principal']} (remove cached copies)"
    if lbl == "Ace":
        return f"remove {'/'.join(a.get('rights') or ['ACL'])} of {a['principal']} on {a['target']}"
    if lbl == "Host":
        return f"add segmentation rule isolating {a['host_id']}"
    return f"remediate {node_id}"


def candidates(store) -> list[str]:
    """Remediable nodes: vulns, credentials, ACEs and hosts that are neither entry points nor crown jewels."""
    out = []
    entry = set(store.entrypoints())  # configured entry hosts are not flagged is_entrypoint
    for n, a in store.g.nodes(data=True):
        if a.get("label") not in CANDIDATE_LABELS:
            continue
        if a.get("label") == "Host" and (a.get("is_entrypoint") or a.get("is_crown_jewel") or n in entry):
            continue
        out.append(n)
    return sorted(out)


def recommend(store, paths: list[AttackPath] | None = None, budget: int = 5,
              cfg: Config | None = None, k: int = 100, exact: bool = True,
              restrict: list[str] | None = None) -> list[Remediation]:
    """Pick <= budget remediations that break the most crown-jewel attack paths.

    Greedy set cover: repeatedly pick the remediable node on the most still-viable paths.
    With ``exact=True`` (default) the exact minimum vertex cut over remediable nodes is also
    computed (max-flow, engine/cuts.py). If it fits in the budget and greedy does not already
    disconnect everything with that many fixes, the greedy is re-run restricted to the cut, so
    the plan provably disconnects every crown jewel with the fewest possible fixes.

    Ties are broken by (fewest crown jewels still reachable after removal, node id), which
    prefers true graph cuts over nodes that merely appear on every *enumerated* path.
    When all enumerated paths are broken, paths are re-enumerated on the reduced graph.
    ``restrict`` limits the plan to these remediable nodes (e.g. only vulnerabilities: a
    patch-only plan); the exact cut is then the minimum cut over them.
    """
    cfg = cfg or store.cfg
    cands = candidates(store)
    if restrict is not None:
        keep = set(restrict)
        cands = [n for n in cands if n in keep]
    greedy = _greedy(store, paths, budget, k, cands)
    if not exact:
        return greedy
    from linchpin.engine.cuts import min_remediation_cut
    cut = min_remediation_cut(store, candidates=cands if restrict is not None else None)
    if not cut or len(cut) > budget:
        return greedy
    g_nodes = [r.target_node for r in greedy]
    if len(g_nodes) <= len(cut) and not store.reachable_crown_jewels(exclude=g_nodes):
        return greedy  # greedy already optimal: keep its (path-coverage) preference among min cuts
    return _greedy(store, paths, budget, k, cut)


def _greedy(store, paths, budget, k, cands) -> list[Remediation]:
    universe: dict[str, AttackPath] = {p.path_id: p for p in (paths or store.k_shortest_paths(k=k))}
    alive = dict(universe)
    removed: list[str] = []
    out: list[Remediation] = []
    for _ in range(budget):
        if not alive:
            fresh = store.k_shortest_paths(k=k, exclude=removed)
            if not fresh:
                break
            for p in fresh:
                universe.setdefault(p.path_id, p)
                alive[p.path_id] = p
        scores = {}
        for n in cands:
            if n in removed:
                continue
            hit = [pid for pid, p in alive.items() if n in p.nodes]
            if hit:
                scores[n] = hit
        if not scores:
            break
        best_hits = max(len(v) for v in scores.values())
        tied = [n for n, v in scores.items() if len(v) == best_hits]
        pick = min(tied, key=lambda n: (len(store.reachable_crown_jewels(exclude=[*removed, n])), n))
        removed.append(pick)
        broken = scores[pick]
        for pid in broken:
            alive.pop(pid, None)
        cuts_all = not store.reachable_crown_jewels(exclude=removed)
        r = Remediation(
            target_node=pick, action=action_for(store, pick), paths_broken=len(broken),
            paths_total=len(universe), residual_paths=len(alive),
            coverage_pct=round(100.0 * len(broken) / len(universe), 2),
            rationale="", evidence=sorted(broken))
        r.rationale = explain_remediation(r, store, list(universe.values()), cuts_all=cuts_all)
        out.append(r)
        if cuts_all:
            break
    return out  # greedy order (non-increasing marginal gain)
