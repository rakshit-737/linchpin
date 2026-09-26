"""M5: greedy set-cover remediation optimizer."""
from __future__ import annotations

from linchpin.config import Config
from linchpin.engine.explain import explain_remediation
from linchpin.models import AttackPath, Remediation

CANDIDATE_LABELS = {"Vuln", "Credential", "Host"}


def action_for(store, node_id: str) -> str:
    a = store.g.nodes[node_id]
    lbl = a.get("label")
    if lbl == "Vuln":
        if a.get("cve") and len(a.get("cves") or []) <= 1:
            return f"patch {a['cve']} on {a['host_id']}"
        what = a.get("name") or a.get("cve") or node_id
        return f"apply fix for '{what}' on {a['host_id']}"
    if lbl == "Credential":
        return f"rotate credential {a['principal']} (remove cached copies)"
    if lbl == "Host":
        return f"add segmentation rule isolating {a['host_id']}"
    return f"remediate {node_id}"


def candidates(store) -> list[str]:
    out = []
    for n, a in store.g.nodes(data=True):
        if a.get("label") not in CANDIDATE_LABELS:
            continue
        if a.get("label") == "Host" and (a.get("is_entrypoint") or a.get("is_crown_jewel")):
            continue
        out.append(n)
    return sorted(out)


def recommend(store, paths: list[AttackPath] | None = None, budget: int = 5,
              cfg: Config | None = None, k: int = 100) -> list[Remediation]:
    """Greedily pick <= budget nodes, each breaking the most still-viable crown-jewel paths.

    Ties are broken by (fewest crown jewels still reachable after removal, node id), which
    prefers true graph cuts over nodes that merely appear on every *enumerated* path.
    When all enumerated paths are broken, paths are re-enumerated on the reduced graph.
    """
    cfg = cfg or store.cfg
    universe: dict[str, AttackPath] = {p.path_id: p for p in (paths or store.k_shortest_paths(k=k))}
    alive = dict(universe)
    removed: list[str] = []
    cands = candidates(store)
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
        pick = min(tied, key=lambda n: (len(store.reachable_crown_jewels(exclude=removed + [n])), n))
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
