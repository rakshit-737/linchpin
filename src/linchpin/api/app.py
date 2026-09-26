"""M7: FastAPI surface over the engines (optional dependency: pip install .[api])."""
from __future__ import annotations

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, ValidationError

from linchpin.config import Config
from linchpin.engine.optimizer import recommend
from linchpin.engine.paths import rank_paths
from linchpin.graph.store import GraphStore
from linchpin.models import AttackPath, BuildStats, NodeDetail, NormalizedFinding, PathStats, Remediation


class WhatIf(BaseModel):
    remove_nodes: list[str]


def create_app(store: GraphStore | None = None) -> FastAPI:
    app = FastAPI(title="LINCHPIN API", version="1.0")
    app.state.store = store or GraphStore(Config())

    @app.post("/ingest")
    def ingest(items: list[dict]):
        ok, bad = [], 0
        for it in items:
            try:
                ok.append(NormalizedFinding.model_validate(it))
            except ValidationError:
                bad += 1
        app.state.store.upsert_findings(ok)
        return {"accepted": len(ok), "rejected": bad,
                "graph_stats": {"findings": len(app.state.store.findings)}}

    @app.post("/graph/build", response_model=BuildStats)
    def build():
        return app.state.store.build_attack_graph()

    @app.get("/paths", response_model=list[AttackPath])
    def paths(k: int = 10, to: str = "crown_jewels"):
        s = app.state.store
        if to == "crown_jewels":
            return rank_paths(s, k=k)
        return s.k_shortest_paths(targets=[to], k=k)

    @app.get("/remediations", response_model=list[Remediation])
    def remediations(budget: int = 5):
        return recommend(app.state.store, budget=budget)

    @app.get("/nodes/{node_id:path}", response_model=NodeDetail)
    def node(node_id: str):
        try:
            return app.state.store.node(node_id)
        except KeyError:
            raise HTTPException(404, f"unknown node {node_id}")

    @app.post("/whatif", response_model=PathStats)
    def whatif(body: WhatIf):
        return app.state.store.remove_nodes_view(body.remove_nodes)

    return app


app = create_app()
