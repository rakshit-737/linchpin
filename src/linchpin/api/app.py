"""M7: FastAPI surface over the engines (optional dependency: ``pip install ".[api]"``).

Frozen endpoints (contracts/openapi.yaml): /ingest, /graph/build, /paths, /remediations,
/nodes/{id}, /whatif. Additive endpoints for the web UI: /graph (Cytoscape elements),
/chokepoints, /criticality, /demo/load, /stats and the static UI at /ui.

There is no authentication: the API binds to localhost by default (``linchpin serve``, the
Makefile, compose) and must not be exposed. Hardening, each limit overridable by environment:

* ``LINCHPIN_ALLOWED_HOSTS`` (default ``127.0.0.1,localhost,::1``): any other ``Host`` header
  gets 400, so a DNS-rebinding page in the analyst's browser cannot talk to the API;
* ``LINCHPIN_MAX_BODY_MB`` (default 25): larger request bodies get 413, also when streamed
  without a ``Content-Length``;
* ``LINCHPIN_MAX_FINDINGS`` (default 200,000 held in total) and ``LINCHPIN_MAX_EDGES``
  (default 1,000,000 attack-graph edges per build): 413 beyond, checked before the work;
* ``k`` / ``budget`` / ``top`` and list sizes are bounded (422 when exceeded);
* ``/demo/load`` accepts a scenario only as a *relative name* under ``LINCHPIN_SCENARIO_DIR``
  (or the configured ``LINCHPIN_SCENARIO``), with exports under ``LINCHPIN_DATA_DIR``; every
  file the scenario lists must stay inside that directory (403 otherwise). Paths are checked
  by their text before the filesystem is touched;
* Swagger UI and ReDoc (which load scripts from a CDN) are served only with
  ``LINCHPIN_API_DOCS=1``; the OpenAPI JSON is always at ``/openapi.json``.
"""
from __future__ import annotations

import json
import os
from collections.abc import Awaitable, Callable, MutableMapping
from pathlib import Path
from typing import Any

from fastapi import FastAPI, HTTPException, Query
from fastapi.responses import FileResponse, RedirectResponse
from pydantic import BaseModel, Field, ValidationError

from linchpin.config import Config
from linchpin.engine.cuts import chokepoints, min_remediation_cut
from linchpin.engine.optimizer import recommend
from linchpin.engine.paths import node_criticality, rank_paths
from linchpin.graph.store import GraphStore, GraphTooLarge
from linchpin.models import (
    AttackPath,
    BuildStats,
    NodeDetail,
    NormalizedFinding,
    PathStats,
    Remediation,
    detail_problem,
)
from linchpin.paths_safe import PathNotAllowed, safe_join

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

STATIC = Path(__file__).parent / "static"
K_MAX = 1000          # paths enumerated per request
BUDGET_MAX = 50       # remediations per plan
INGEST_MAX = 200_000  # findings per /ingest call
REMOVE_MAX = 1000     # nodes per what-if
DEFAULT_HOSTS = "127.0.0.1,localhost,::1"


def _env_int(name: str, default: int) -> int:
    return int(float(os.environ.get(name, default)))


class WhatIf(BaseModel):
    """Body of ``POST /whatif``: node ids to remove (nothing is persisted)."""
    remove_nodes: list[str] = Field(max_length=REMOVE_MAX)


class DemoLoad(BaseModel):
    """Body of ``POST /demo/load``: a synthetic family and seed, or the server's scenario."""
    family: str = Field("single", max_length=32)  # single | multi | none | ad | scenario
    seed: int = Field(0, ge=0, le=1_000_000)
    n_hosts: int = Field(20, ge=1, le=10_000)  # clamped to 8..200 below
    scenario: str | None = Field(None, max_length=256)  # name relative to LINCHPIN_SCENARIO_DIR
    data_dir: str | None = Field(None, max_length=256)  # sub-directory of LINCHPIN_DATA_DIR


def _host_of(header: str) -> str:
    """Host name of a ``Host`` header without the port (IPv6 literals keep no brackets)."""
    h = header.strip().lower()
    if h.startswith("["):
        return h[1:h.find("]")] if "]" in h else h
    return h.rsplit(":", 1)[0] if h.count(":") == 1 else h


class HostAllowList:
    """Pure-ASGI middleware: answer 400 unless the ``Host`` header names an allowed host."""

    def __init__(self, app: ASGIApp, allowed: list[str]) -> None:
        self.app = app
        self.allowed = {_host_of(h) for h in allowed if h.strip()}
        self.any = "*" in self.allowed

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:  # noqa: D102 - ASGI entry
        if self.any or scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)
        host = _host_of(dict(scope.get("headers") or []).get(b"host", b"").decode("latin-1"))
        if host in self.allowed:
            return await self.app(scope, receive, send)
        await _reject(send, 400, "Host header not allowed (set LINCHPIN_ALLOWED_HOSTS)")


class BodySizeLimit:
    """Pure-ASGI middleware: refuse request bodies larger than ``max_bytes`` with 413."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:  # noqa: D102 - ASGI entry
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        declared = dict(scope.get("headers") or []).get(b"content-length")
        if declared is not None and declared.isdigit() and int(declared) > self.max_bytes:
            return await _reject(send, 413, f"request body exceeds {self.max_bytes} bytes")
        seen = 0

        async def limited() -> Message:
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > self.max_bytes:
                    raise HTTPException(413, f"request body exceeds {self.max_bytes} bytes")
            return msg

        return await self.app(scope, limited, send)


async def _reject(send: Send, status: int, detail: str) -> None:
    body = json.dumps({"detail": detail}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


def _confined(requested: str | None, default_env: str, root_env: str, what: str) -> str | None:
    """Server-side path for a request: the configured default, or a relative name under the root.

    The client never supplies an absolute path; a requested name is validated by its text and
    joined to ``$root_env`` (:func:`linchpin.paths_safe.safe_join`) before anything is opened.
    """
    if not requested:
        return os.environ.get(default_env)
    root = os.environ.get(root_env)
    if not root:
        raise HTTPException(403, f"{what} names are only accepted when {root_env} is set on the server")
    try:
        return str(safe_join(root, requested))
    except PathNotAllowed as e:
        raise HTTPException(403, f"{what}: {e} (use a name relative to {root_env})") from None


def _load(findings: list[NormalizedFinding], cfg: Config) -> GraphStore:
    s = GraphStore(cfg)
    s.upsert_findings(findings)
    try:
        s.build_attack_graph(max_edges=_env_int("LINCHPIN_MAX_EDGES", 1_000_000))
    except GraphTooLarge as e:
        raise HTTPException(413, str(e)) from None
    return s


def _node_ref(s: GraphStore, ref: str) -> str:
    """Accept a node id or a bare host name (``web-01`` -> ``host:web-01``)."""
    return ref if ref in s.g or f"host:{ref}" not in s.g else f"host:{ref}"


def create_app(store: GraphStore | None = None, loaded: str = "") -> FastAPI:
    """Build the FastAPI app around ``store`` (an empty in-memory store by default)."""
    docs = os.environ.get("LINCHPIN_API_DOCS") == "1"
    app = FastAPI(title="LINCHPIN API", version="1.2",
                  description="Read-only attack-path reasoning. Consumes exported findings; sends no packets.",
                  docs_url="/docs" if docs else None, redoc_url="/redoc" if docs else None)
    app.add_middleware(BodySizeLimit, max_bytes=int(float(os.environ.get("LINCHPIN_MAX_BODY_MB", "25")) * 2**20))
    app.add_middleware(HostAllowList, allowed=os.environ.get("LINCHPIN_ALLOWED_HOSTS", DEFAULT_HOSTS).split(","))
    app.state.store = store or GraphStore(Config())
    app.state.loaded = loaded

    def S() -> GraphStore:
        return app.state.store

    # ------------------------------------------------------------ frozen API
    @app.post("/ingest")
    def ingest(items: list[dict]) -> dict:
        """Validate and add findings; invalid records are counted as rejected (with reasons)."""
        if len(items) > INGEST_MAX:
            raise HTTPException(413, f"at most {INGEST_MAX} findings per request")
        ok: list[NormalizedFinding] = []
        reasons: list[str] = []
        for it in items:
            try:
                f = NormalizedFinding.model_validate(it)
            except ValidationError as e:
                reasons.append(str(e.errors()[0].get("msg")))
                continue
            problem = detail_problem(f)
            if problem:
                reasons.append(problem)
                continue
            ok.append(f)
        cap = _env_int("LINCHPIN_MAX_FINDINGS", 200_000)
        new = {f.finding_id for f in ok} - set(S().findings)
        if len(S().findings) + len(new) > cap:
            raise HTTPException(413, f"the store would hold more than {cap} findings (LINCHPIN_MAX_FINDINGS)")
        S().upsert_findings(ok)
        return {"accepted": len(ok), "rejected": len(reasons), "rejected_reasons": sorted(set(reasons))[:20],
                "graph_stats": {"findings": len(S().findings)}}

    @app.post("/graph/build", response_model=BuildStats)
    def build() -> BuildStats:
        try:
            return S().build_attack_graph(max_edges=_env_int("LINCHPIN_MAX_EDGES", 1_000_000))
        except GraphTooLarge as e:
            raise HTTPException(413, str(e)) from None

    @app.get("/paths", response_model=list[AttackPath])
    def paths(k: int = Query(10, ge=1, le=K_MAX),
              to: str = Query("crown_jewels", max_length=512, description="crown_jewels or a node id"),
              frm: str | None = Query(None, alias="from", max_length=512,
                                      description="entrypoints (default) or a node id"),
              frm_legacy: str | None = Query(None, alias="frm", max_length=512, include_in_schema=False)
              ) -> list[AttackPath]:
        s = S()
        src = frm or frm_legacy
        sources = None if src in (None, "entrypoints") else [_node_ref(s, src)]
        if to == "crown_jewels":
            return rank_paths(s, k=k) if sources is None else s.k_shortest_paths(sources=sources, k=k)
        return s.k_shortest_paths(sources=sources, targets=[_node_ref(s, to)], k=k)

    @app.get("/remediations", response_model=list[Remediation])
    def remediations(budget: int = Query(5, ge=1, le=BUDGET_MAX),
                     k: int = Query(100, ge=1, le=K_MAX)) -> list[Remediation]:
        return recommend(S(), budget=budget, k=k)

    @app.get("/nodes/{id:path}", response_model=NodeDetail)
    def node(id: str) -> NodeDetail:  # parameter name frozen by contracts/openapi.yaml
        try:
            return S().node(id)
        except KeyError:
            raise HTTPException(404, f"unknown node {id}") from None

    @app.post("/whatif", response_model=PathStats)
    def whatif(body: WhatIf) -> PathStats:
        return S().remove_nodes_view(body.remove_nodes)

    # ---------------------------------------------------------- UI helpers
    @app.get("/graph")
    def graph() -> dict:
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
    def chokes(weighted: bool = False) -> dict:
        mc = min_remediation_cut(S())
        out = {"chokepoints": chokepoints(S()), "min_cut": mc, "min_cut_size": None if mc is None else len(mc)}
        if weighted:
            out["weighted_cut"] = min_remediation_cut(S(), weighted=True)
        return out

    @app.get("/criticality")
    def criticality(k: int = Query(50, ge=1, le=K_MAX), top: int = Query(15, ge=1, le=1000)) -> list:
        return list(node_criticality(rank_paths(S(), k=k)).items())[:top]

    @app.get("/stats")
    def stats() -> dict:
        s = S()
        return {"findings": len(s.findings), "nodes": s.g.number_of_nodes(), "edges": s.g.number_of_edges(),
                "entrypoints": s.entrypoints(), "crown_jewels": s.crown_jewels(),
                "reachable_crown_jewels": s.reachable_crown_jewels(), "loaded": app.state.loaded}

    @app.post("/demo/load")
    def demo_load(body: DemoLoad) -> dict:
        if body.family == "scenario":
            from linchpin.scenario import load_scenario
            path = _confined(body.scenario, "LINCHPIN_SCENARIO", "LINCHPIN_SCENARIO_DIR", "scenario")
            data_dir = _confined(body.data_dir, "LINCHPIN_DATA_DIR", "LINCHPIN_DATA_DIR", "data")
            if not path or not Path(path).is_file():
                raise HTTPException(400, "no scenario configured on the server (set LINCHPIN_SCENARIO)")
            try:
                findings, cfg, meta = load_scenario(path, data_dir, confine=True)
            except PathNotAllowed as e:
                raise HTTPException(403, f"scenario lists a file outside its data directory: {e}") from None
            except (FileNotFoundError, ValueError) as e:
                raise HTTPException(400, f"scenario could not be loaded: {type(e).__name__}") from None
            app.state.store = _load(findings, cfg)
            app.state.loaded = "scenario:" + str(meta.get("name", ""))
        else:
            from linchpin.synth.topologies import FAMILIES, generate_family
            if body.family not in FAMILIES:
                raise HTTPException(400, f"family must be one of {FAMILIES} or 'scenario'")
            findings, gt = generate_family(body.family, max(8, min(body.n_hosts, 200)), body.seed)
            app.state.store = _load(findings, Config())
            app.state.loaded = f"{body.family}:{body.seed}"
            meta = gt.model_dump()
        return {"meta": meta, **stats()}

    @app.get("/", include_in_schema=False)
    def root() -> RedirectResponse:
        return RedirectResponse("/ui")

    @app.get("/ui", include_in_schema=False)
    def ui() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    return app


def _default_app() -> FastAPI:
    """App for ``uvicorn linchpin.api.app:app``: preloads LINCHPIN_SCENARIO if set, else a synth demo."""
    path = os.environ.get("LINCHPIN_SCENARIO")
    if path and Path(path).exists():
        from linchpin.scenario import load_scenario
        findings, cfg, meta = load_scenario(path, os.environ.get("LINCHPIN_DATA_DIR"))
        return create_app(_load(findings, cfg), loaded=f"scenario:{meta['name']}")
    if os.environ.get("LINCHPIN_DEMO", "1") == "1":
        from linchpin.synth.topologies import generate_family
        findings, _ = generate_family("single", 20, 0)
        return create_app(_load(findings, Config()), loaded="single:0")
    return create_app()


app = _default_app()
