"""M2: GraphStore. In-memory NetworkX backend (Neo4j backend is a documented TODO).

This is the ONLY module that knows how the graph is stored; engines go through it.
"""
from __future__ import annotations

import hashlib
import itertools
import time
from typing import Iterable

import networkx as nx

from linchpin.config import Config
from linchpin.engine.edge_cost import EdgeContext, edge_cost
from linchpin.models import AttackPath, BuildStats, NodeDetail, NormalizedFinding, PathStats

INTERNET = "internet"
_SRC, _SNK = "__src__", "__snk__"

STAGE_BY_REL = {
    "CAN_REACH": "lateral",
    "HAS_VULN": "exploit",
    "ENABLES": "exploit",
    "LEADS_TO": "privesc",
    "STORED_ON": "privesc",
    "GRANTS": "lateral",
    "HOLDS": "objective",
}
CLASS_BY_REL = {"ENABLES": "network_exploit", "GRANTS": "cred_reuse", "STORED_ON": "privesc"}


def edge_id(u: str, rel: str, v: str) -> str:
    return f"{u}|{rel}|{v}"


class GraphStore:
    def __init__(self, cfg: Config | None = None):
        self.cfg = cfg or Config()
        self.findings: dict[str, NormalizedFinding] = {}
        self.g = nx.DiGraph()

    # ---------------------------------------------------------------- ingest
    def upsert_findings(self, findings: Iterable[NormalizedFinding]) -> None:
        for f in findings:
            self.findings[f.finding_id] = f

    # ----------------------------------------------------------------- build
    def build_attack_graph(self) -> BuildStats:
        t0 = time.perf_counter()
        g = nx.DiGraph()
        hosts: dict[str, dict] = {}
        services: dict[str, list[tuple[int, str]]] = {}
        reach: list[dict] = []
        fs = sorted(self.findings.values(), key=lambda f: f.finding_id)

        def host(hid: str) -> str:
            nid = f"host:{hid}"
            if hid not in hosts:
                hosts[hid] = {"segment": "default", "os": None, "internet_facing": False}
                g.add_node(nid, label="Host", host_id=hid)
            return nid

        def service(hid: str, port: int, f: NormalizedFinding | None = None) -> str:
            host(hid)
            nid = f"svc:{hid}:{port}"
            if nid not in g:
                g.add_node(nid, label="Service", host_id=hid, port=port, proto="tcp",
                           software=f.software if f else None, version=f.version if f else None,
                           service=f.service if f else None)
                services.setdefault(hid, []).append((port, nid))
            return nid

        def priv(hid: str) -> str:
            nid = f"priv:admin@{hid}"
            if nid not in g:
                g.add_node(nid, label="Privilege", principal="*", level="local-admin", host_id=hid)
                self._add(g, nid, "LEADS_TO", host(hid))
            return nid

        for f in fs:
            d = f.detail or {}
            if f.kind == "config" and d.get("issue") == "inventory":
                host(f.host_id)
                # Topology-overlay facts (source=inventory) take precedence over what a
                # collector (e.g. BloodHound) guessed; only keys actually present are applied.
                upd = {k: d[k] for k in ("segment", "os", "internet_facing") if d.get(k) is not None}
                if "internet_facing" in upd:
                    upd["internet_facing"] = bool(upd["internet_facing"])
                if f.source == "inventory":
                    hosts[f.host_id]["_overlay"] = set(upd)
                else:
                    upd = {k: v for k, v in upd.items() if k not in hosts[f.host_id].get("_overlay", ())}
                hosts[f.host_id].update(upd)
                if d.get("is_dc"):
                    hosts[f.host_id]["is_dc"] = True
                for ds in d.get("datastores", []):
                    dsid = f"ds:{ds['name']}"
                    g.add_node(dsid, label="DataStore", sensitivity=ds.get("sensitivity", "low"),
                               host_id=f.host_id)
                    self._add(g, host(f.host_id), "HOLDS", dsid)
            elif f.kind == "service" and f.port is not None:
                service(f.host_id, f.port, f)
            elif f.kind == "cve" and (f.cve_id or d.get("vuln_id")):
                svc = service(f.host_id, f.port or 0, f)
                key = d.get("vuln_id") or f.cve_id
                vid = f"vuln:{key}@{f.host_id}:{f.port or 0}"
                impact = d.get("impact_class")
                g.add_node(vid, label="Vuln", cve=f.cve_id, cvss_base=f.cvss_base, epss=f.epss,
                           exploit_maturity=d.get("exploit_maturity"), kev=bool(d.get("kev")),
                           name=d.get("name"), cves=d.get("cves") or ([f.cve_id] if f.cve_id else []),
                           impact_class=impact, host_id=f.host_id)
                self._add(g, svc, "HAS_VULN", vid)
                # Only vulns that plausibly yield code execution grant a privilege. Unknown
                # impact (no CVSS vector) is treated conservatively as code execution.
                if impact in (None, "rce"):
                    self._add(g, vid, "ENABLES", priv(f.host_id), cvss_base=f.cvss_base, epss=f.epss,
                              cvss_exploitability=d.get("cvss_exploitability"), kev=bool(d.get("kev")))
            elif f.kind == "credential":
                cid = f"cred:{d['principal']}"
                g.add_node(cid, label="Credential", principal=d["principal"],
                           cred_type=d.get("cred_type", "password"))
                self._add(g, host(f.host_id), "STORED_ON", cid)
                for target in d.get("valid_on", []):
                    self._add(g, cid, "GRANTS", priv(target))
            elif f.kind == "acl" and d.get("right") == "AdminTo":
                cid = f"cred:{d['principal']}"
                if cid not in g:
                    g.add_node(cid, label="Credential", principal=d["principal"], cred_type="unknown")
                self._add(g, cid, "GRANTS", priv(d["target"]))
            elif f.kind == "reachability" and d.get("allowed", True):
                reach.append(d)

        for hid, props in hosts.items():
            props.pop("_overlay", None)
            g.nodes[f"host:{hid}"].update(props)

        # Reachability: same segment always; cross-segment only via explicit rules.
        rules = {(r["from_segment"], r["to_segment"]): set(r.get("ports") or []) for r in reach}
        for a, b in itertools.permutations(hosts, 2):
            sa, sb = hosts[a]["segment"], hosts[b]["segment"]
            rule = rules.get((sa, sb))
            for port, svc in services.get(b, []):
                if sa == sb or (rule is not None and (not rule or port in rule)):
                    self._add(g, f"host:{a}", "CAN_REACH", svc)
        facing = sorted(h for h, p in hosts.items() if p["internet_facing"])
        if facing:
            g.add_node(INTERNET, label="Internet")
            for h in facing:
                for _, svc in services.get(h, []):
                    self._add(g, INTERNET, "CAN_REACH", svc)

        self.g = g
        for n in self.crown_jewels():
            g.nodes[n]["is_crown_jewel"] = True
            hid = g.nodes[n].get("host_id")
            if hid:
                g.nodes[f"host:{hid}"]["is_crown_jewel"] = True
        for h in facing:
            g.nodes[f"host:{h}"]["is_entrypoint"] = True
        return BuildStats(nodes=g.number_of_nodes(), edges=g.number_of_edges(),
                          build_ms=round((time.perf_counter() - t0) * 1000, 2))

    def _add(self, g: nx.DiGraph, u: str, rel: str, v: str, **props) -> None:
        ctx = EdgeContext(rel=rel, transition_class=CLASS_BY_REL.get(rel),
                          cvss_base=props.get("cvss_base"), epss=props.get("epss"),
                          cvss_exploitability=props.get("cvss_exploitability"), kev=bool(props.get("kev")))
        g.add_edge(u, v, rel=rel, id=edge_id(u, rel, v), cost=edge_cost(ctx, self.cfg), **props)

    # --------------------------------------------------------- entry / crown
    def entrypoints(self) -> list[str]:
        out: list[str] = []
        for e in self.cfg.entrypoints:
            if e == "auto:internet_facing":
                if INTERNET in self.g:
                    out.append(INTERNET)
            elif e in self.g:
                out.append(e)
            elif f"host:{e}" in self.g:
                out.append(f"host:{e}")
        return sorted(set(out))

    def crown_jewels(self) -> list[str]:
        out: list[str] = []
        for c in self.cfg.crown_jewels:
            if c.startswith("auto:sensitivity="):
                lvl = c.split("=", 1)[1]
                out += [n for n, a in self.g.nodes(data=True)
                        if a.get("label") == "DataStore" and a.get("sensitivity") == lvl]
            elif c in self.g:
                out.append(c)
            elif f"host:{c}" in self.g:
                out.append(f"host:{c}")
        return sorted(set(out))

    # ----------------------------------------------------------------- paths
    def k_shortest_paths(self, sources=None, targets=None, k: int | None = None,
                         exclude: Iterable[str] = ()) -> list[AttackPath]:
        """Yen's k-shortest simple paths (by summed edge cost) from any source to any target."""
        k = k or self.cfg.k_shortest
        g = self.g.copy()
        g.remove_nodes_from([n for n in exclude if n in g])
        sources = [s for s in (sources or self.entrypoints()) if s in g]
        targets = [t for t in (targets or self.crown_jewels()) if t in g]
        if not sources or not targets:
            return []
        for s in sources:
            g.add_edge(_SRC, s, cost=0.0)
        for t in targets:
            g.add_edge(t, _SNK, cost=0.0)
        out: list[AttackPath] = []
        try:
            for raw in itertools.islice(nx.shortest_simple_paths(g, _SRC, _SNK, weight="cost"), k):
                nodes = raw[1:-1]
                pairs = list(zip(nodes, nodes[1:]))
                rels = [g.edges[u, v]["rel"] for u, v in pairs]
                out.append(AttackPath(
                    path_id=hashlib.sha1("|".join(nodes).encode()).hexdigest()[:12],
                    nodes=nodes,
                    edges=[g.edges[u, v]["id"] for u, v in pairs],
                    stages=[("recon" if u == INTERNET else STAGE_BY_REL[r]) for (u, _), r in zip(pairs, rels)],
                    crown_jewel=nodes[-1],
                    total_cost=round(sum(g.edges[u, v]["cost"] for u, v in pairs), 6)))
        except nx.NetworkXNoPath:
            pass
        return out

    def reachable_crown_jewels(self, exclude: Iterable[str] = ()) -> list[str]:
        g = self.g.copy()
        g.remove_nodes_from([n for n in exclude if n in g])
        seen: set[str] = set()
        for s in self.entrypoints():
            if s in g:
                seen |= nx.descendants(g, s) | {s}
        return [c for c in self.crown_jewels() if c in seen]

    # ------------------------------------------------------------ inspection
    def node(self, node_id: str) -> NodeDetail:
        if node_id not in self.g:
            raise KeyError(node_id)
        a = dict(self.g.nodes[node_id])
        return NodeDetail(
            id=node_id, label=a.pop("label", "?"), props=a,
            inbound=[{"from": u, "rel": d["rel"], "cost": d["cost"]}
                     for u, _, d in self.g.in_edges(node_id, data=True)],
            outbound=[{"to": v, "rel": d["rel"], "cost": d["cost"]}
                      for _, v, d in self.g.out_edges(node_id, data=True)],
        )

    def remove_nodes_view(self, ids: list[str], k: int = 100) -> PathStats:
        """What-if: recompute path stats with nodes removed. Never mutates the store."""
        before = self.k_shortest_paths(k=k)
        after = self.k_shortest_paths(k=k, exclude=ids)
        return PathStats(
            removed=ids, paths_before=len(before), paths_after=len(after),
            reachable_crown_jewels_before=self.reachable_crown_jewels(),
            reachable_crown_jewels_after=self.reachable_crown_jewels(exclude=ids),
            min_cost_before=before[0].total_cost if before else None,
            min_cost_after=after[0].total_cost if after else None,
        )
