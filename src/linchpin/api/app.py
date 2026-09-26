"""M7: FastAPI surface over the engines (optional dependency: pip install .[api]).

Frozen endpoints (contracts/openapi.yaml): /ingest, /graph/build, /paths, /remediations,
/nodes/{id}, /whatif. Additive endpoints for the web UI: /graph (Cytoscape elements),
/chokepoints, /criticality, /demo/load, /stats and the static UI at /ui.

Binds to localhost by default (see Makefile / README); there is no auth, so never expose it.
"""
from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel, ValidationError

from linchpin.config import Config
from linchpin.engine.cuts import chokepoints, min_remediation_cut
from linchpin.engine.optimizer import recommend
from linchpin.engine.paths import node_criticality, rank_paths
from linchpin.graph.store import GraphStore
from linchpin.models import AttackPath, BuildStats, NodeDetail, NormalizedFinding, PathStats, Remediation

STATIC = Path(__file__).parent / "static"


class WhatIf(BaseModel):
    remove_nodes: list[str]


class DemoLoad(BaseModel):
    family: str = "single"  # single | multi | none | ad | scenario
    seed: int = 0
    n_hosts: int = 20
    scenario: str | None = None  # path to a scenario YAML (server-side), with family="scenario"
    data_dir: str | None = None


def _load(store: GraphStore, findings, cfg: Config | None = None) -> GraphStore:
    s = GraphStore(cfg or store.cfg)
    s.upsert_findings(findings)
    s.build_attack_graph()
    return s


def create_app(store: GraphStore | None = None, loaded: str = "") -> FastAPI:
    app = FastAPI(title="LINCHPIN API", version="1.2",
                  description="Read-only attack-path reasoning. Consumes exported findings; sends no packets.")
    app.state.store = store or GraphStore(Config())
    app.state.loaded = loaded

    def S() -> GraphStore:
        return app.state.store

    # ------------------------------------------------------------ frozen API
    @app.post("/ingest")
    def ingest(items: list[dict]):
        ok, bad = [], 0
        for it in items:
            try:
                ok.append(NormalizedFinding.model_validate(it))
            except ValidationError:
                bad += 1
        S().upsert_findings(ok)
        return {"accepted": len(ok), "rejected": bad, "graph_stats": {"findings": len(S().findings)}}

    @app.post("/graph/build", response_model=BuildStats)
    def build():
        return S().build_attack_graph()

    @app.get("/paths", response_model=list[AttackPath])
    def paths(k: int = 10, to: str = "crown_jewels", frm: str | None = None):
        s = S()
        sources = None if frm in (None, "entrypoints") else [frm]
        if to == "crown_jewels":
            return rank_paths(s, k=k) if sources is None else s.k_shortest_paths(sources=sources, k=k)
        return s.k_shortest_paths(sources=sources, targets=[to], k=k)

    @app.get("/remediations", response_model=list[Remediation])
    def remediations(budget: int = 5, k: int = 100):
        return recommend(S(), budget=budget, k=k)

    @app.get("/nodes/{node_id:path}", response_model=NodeDetail)
    def node(node_id: str):
        try:
            return S().node(node_id)
        except KeyError:
            raise HTTPException(404, f"unknown node {node_id}")

    @app.post("/whatif", response_model=PathStats)
    def whatif(body: WhatIf):
        return S().remove_nodes_view(body.remove_nodes)

    # ---------------------------------------------------------- UI helpers
    @app.get("/graph")
    def graph():
        s = S()
        crowns, entries = set(s.crown_jewels()), set(s.entrypoints())
        nodes = []
        for n, a in s.g.nodes(data=True):
            d = {"id": n, "label": a.get("label", "?"), "name": n.split(":", 1)[-1] if ":" in n else n,
                 "segment": a.get("segment") or (s.g.nodes.get(f"host:{a.get('host_id')}", {}).get("segment")),
                 "crown": n in crowns, "entry": n in entries, "kev": bool(a.get("kev")),
                 "cvss": a.get("cvss_base"), "epss": a.get("epss")}
            nodes.append({"data": d})
        edges = [{"data": {"id": a["id"], "source": u, "target": v, "rel": a["rel"], "cost": a["cost"]}}
                 for u, v, a in s.g.edges(data=True)]
        return {"nodes": nodes, "edges": edges}

    @app.get("/chokepoints")
    def chokes(weighted: bool = False):
        mc = min_remediation_cut(S())
        out = {"chokepoints": chokepoints(S()), "min_cut": mc, "min_cut_size": None if mc is None else len(mc)}
        if weighted:
            out["weighted_cut"] = min_remediation_cut(S(), weighted=True)
        return out

    @app.get("/criticality")
    def criticality(k: int = 50, top: int = 15):
        return list(node_criticality(rank_paths(S(), k=k)).items())[:top]

    @app.get("/stats")
    def stats():
        s = S()
        return {"findings": len(s.findings), "nodes": s.g.number_of_nodes(), "edges": s.g.number_of_edges(),
                "entrypoints": s.entrypoints(), "crown_jewels": s.crown_jewels(),
                "reachable_crown_jewels": s.reachable_crown_jewels(), "loaded": app.state.loaded}

    @app.post("/demo/load")
    def demo_load(body: DemoLoad):
        if body.family == "scenario":
            from linchpin.scenario import load_scenario
            path = body.scenario or os.environ.get("LINCHPIN_SCENARIO")
            if not path or not Path(path).exists():
                raise HTTPException(400, "scenario path missing or not found on the server")
            findings, cfg, meta = load_scenario(path, body.data_dir or os.environ.get("LINCHPIN_DATA_DIR"))
            app.state.store = _load(S(), findings, cfg)
            app.state.loaded = "scenario:" + str(meta.get("name", ""))
        else:
            from linchpin.synth.topologies import FAMILIES, generate_family
            if body.family not in FAMILIES:
                raise HTTPException(400, f"family must be one of {FAMILIES} or 'scenario'")
            findings, gt = generate_family(body.family, max(8, min(body.n_hosts, 200)), body.seed)
            app.state.store = _load(S(), findings, Config())
            app.state.loaded = f"{body.family}:{body.seed}"
            meta = gt.model_dump()
        return {"meta": meta, **stats()}

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse("/ui")

    @app.get("/ui", include_in_schema=False)
    def ui():
        return FileResponse(STATIC / "index.html")

    return app


def _default_app() -> FastAPI:
    """App for `uvicorn linchpin.api.app:app`; preloads LINCHPIN_SCENARIO if set, else a synth demo."""
    path = os.environ.get("LINCHPIN_SCENARIO")
    if path and Path(path).exists():
        from linchpin.scenario import load_scenario
        findings, cfg, meta = load_scenario(path, os.environ.get("LINCHPIN_DATA_DIR"))
        return create_app(_load(GraphStore(cfg), findings, cfg), loaded=f"scenario:{meta['name']}")
    elif os.environ.get("LINCHPIN_DEMO", "1") == "1":
        from linchpin.synth.topologies import generate_family
        findings, _ = generate_family("single", 20, 0)
        return create_app(_load(GraphStore(Config()), findings, Config()), loaded="single:0")
    return create_app()


app = _default_app()
