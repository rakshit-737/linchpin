"""M6: deterministic, template-based explanations (no LLM)."""
from __future__ import annotations

import itertools

from linchpin.models import AttackPath, Remediation


def _label(store, node_id: str) -> str:
    return store.g.nodes[node_id].get("label", "?") if node_id in store.g else "?"


def _segments_around(store, node_id: str, paths: list[AttackPath]) -> tuple[set[str], set[str]]:
    before, after = set(), set()
    for p in paths:
        if node_id not in p.nodes:
            continue
        i = p.nodes.index(node_id)
        hosts = [(j, n) for j, n in enumerate(p.nodes) if n.startswith("host:") and n != node_id]
        prev = [n for j, n in hosts if j < i]
        nxt = [n for j, n in hosts if j > i]
        if prev:
            before.add(store.g.nodes[prev[-1]].get("segment", "?"))
        elif p.nodes[0] == "internet":
            before.add("internet")
        if nxt:
            after.add(store.g.nodes[nxt[0]].get("segment", "?"))
    return before, after


def explain_remediation(r: Remediation, store, paths: list[AttackPath] | None = None,
                        cuts_all: bool = False) -> str:
    paths = paths or []
    crowns = sorted({p.crown_jewel for p in paths if p.path_id in set(r.evidence)}) or ["the crown jewels"]
    crown = ", ".join(crowns)
    label = _label(store, r.target_node)
    tail = f"{r.action} breaks {r.paths_broken}/{r.paths_total} enumerated attack paths to {crown}."
    if label == "Host":
        before, after = _segments_around(store, r.target_node, paths)
        seg = store.g.nodes[r.target_node].get("segment", "?")
        role = "the only pivot" if cuts_all else "a shared pivot"
        return (f"{r.target_node} (segment {seg}) is {role} from {', '.join(sorted(before)) or '?'} "
                f"to {', '.join(sorted(after)) or '?'}; {tail}")
    if label == "Vuln":
        a = store.g.nodes[r.target_node]
        kev = ", CISA KEV" if a.get("kev") else ""
        name = a.get("cve") or a.get("name")
        return (f"{name} on {a.get('host_id')} (CVSS {a.get('cvss_base')}, EPSS {a.get('epss')}{kev}) "
                f"is a step on {r.paths_broken} attack paths; {tail}")
    if label == "Ace":
        a = store.g.nodes[r.target_node]
        return (f"{a.get('principal')} holds {', '.join(a.get('rights') or [])} on {a.get('target_kind')} "
                f"{a.get('target')} (abusable AD ACL); {tail}")
    if label == "Credential":
        g = store.g
        cached = sorted(u.split(":", 1)[1] for u in g.predecessors(r.target_node)
                        if g.edges[u, r.target_node].get("rel") == "STORED_ON")
        grants = sorted(v.split("@", 1)[-1] for v in g.successors(r.target_node)
                        if g.edges[r.target_node, v].get("rel") == "GRANTS")
        where = f"is recoverable on {', '.join(cached)}" if cached else "is exposed"
        what = f"grants admin on {len(grants)} host(s) ({', '.join(grants[:4])}{', ...' if len(grants) > 4 else ''})"
        return f"Credential {r.target_node.split(':', 1)[1]} {where} and {what}; {tail}"
    return tail


def explain_path(p: AttackPath, store) -> str:
    hops = [f"{u} -[{e.split('|')[1]}/{s}]-> {v}"
            for (u, v), e, s in zip(itertools.pairwise(p.nodes), p.edges, p.stages, strict=True)]
    return (f"Path {p.path_id} (cost {p.total_cost:.3f}) reaches {p.crown_jewel} in {len(p.edges)} hops: "
            + "; ".join(hops))
