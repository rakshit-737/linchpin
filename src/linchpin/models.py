"""Frozen contract models (see contracts/)."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

Kind = Literal["cve", "service", "credential", "acl", "config", "reachability"]
Stage = Literal["recon", "exploit", "privesc", "lateral", "objective"]


def make_finding_id(host_id: str, kind: str, key: str) -> str:
    """Stable finding id: the first 16 hex digits of ``sha256(host_id|kind|key)``."""
    return hashlib.sha256(f"{host_id}|{kind}|{key}".encode()).hexdigest()[:16]


def now_iso() -> str:
    """Current UTC time in ISO-8601."""
    return datetime.now(timezone.utc).isoformat()


class NormalizedFinding(BaseModel):
    """The one schema every connector emits (contracts/finding.schema.json)."""
    finding_id: str
    host_id: str
    kind: Kind
    cve_id: str | None = Field(default=None, pattern=r"^CVE-\d{4}-\d+$")
    cvss_base: float | None = Field(default=None, ge=0, le=10)
    cvss_vector: str | None = None
    epss: float | None = Field(default=None, ge=0, le=1)
    port: int | None = None
    service: str | None = None
    software: str | None = None
    version: str | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
    source: str
    observed_at: str


def detail_problem(f: NormalizedFinding) -> str | None:
    """Why ``f.detail`` cannot be used to build the attack graph, or None when it is usable.

    The schema leaves ``detail`` free-form; the graph builder needs these keys per kind:
    ``credential`` -> ``principal`` (and a list ``valid_on`` if given); ``acl`` -> ``principal``
    plus ``target`` (AdminTo) or ``target_name`` (abusable ACE); ``reachability`` ->
    ``from_segment`` and ``to_segment`` (and a list of integer ``ports`` if given); inventory
    ``config`` -> ``datastores`` as a list of objects with a ``name``.
    """
    d = f.detail or {}

    def text(key: str) -> bool:
        return isinstance(d.get(key), str) and bool(d[key])

    if f.kind == "credential":
        if not text("principal"):
            return "credential detail needs a non-empty 'principal'"
        if not isinstance(d.get("valid_on", []), list):
            return "credential 'valid_on' must be a list of host ids"
    elif f.kind == "acl":
        if not text("principal"):
            return "acl detail needs a non-empty 'principal'"
        if d.get("ace") and not text("target_name"):
            return "ACE detail needs 'target_name'"
        if d.get("right") == "AdminTo" and not text("target"):
            return "AdminTo detail needs 'target'"
    elif f.kind == "reachability":
        if not (text("from_segment") and text("to_segment")):
            return "reachability detail needs 'from_segment' and 'to_segment'"
        ports = d.get("ports") or []
        if not isinstance(ports, list) or not all(isinstance(p, int) and not isinstance(p, bool) for p in ports):
            return "reachability 'ports' must be a list of integers"
    elif f.kind == "config" and d.get("issue") == "inventory":
        ds = d.get("datastores") or []
        if not isinstance(ds, list) or not all(isinstance(x, dict) and x.get("name") for x in ds):
            return "inventory 'datastores' must be a list of objects with a 'name'"
    return None


class AttackPath(BaseModel):
    """An entry-to-crown-jewel path: node and edge ids in order, total cost, kill-chain stage per hop."""
    path_id: str
    nodes: list[str]
    edges: list[str]
    total_cost: float
    stages: list[Stage]
    crown_jewel: str


class Remediation(BaseModel):
    """One fix in a plan: target node, action, paths broken out of the total, rationale and evidence."""
    target_node: str
    action: str
    paths_broken: int
    paths_total: int
    residual_paths: int
    coverage_pct: float
    rationale: str
    evidence: list[str]


class BuildStats(BaseModel):
    """Size and build time of an attack graph."""
    nodes: int
    edges: int
    build_ms: float


class NodeDetail(BaseModel):
    """A node's properties and its inbound / outbound attack edges."""
    id: str
    label: str
    props: dict[str, Any]
    inbound: list[dict[str, Any]]
    outbound: list[dict[str, Any]]


class PathStats(BaseModel):
    """What-if result: paths and reachable crown jewels before and after removing nodes."""
    removed: list[str]
    paths_before: int
    paths_after: int
    reachable_crown_jewels_before: list[str]
    reachable_crown_jewels_after: list[str]
    min_cost_before: float | None
    min_cost_after: float | None


class GroundTruth(BaseModel):
    """Answer key of a synthetic topology: planted linchpin / cut, entry points, crown jewels, provenance."""
    linchpin: str  # planted single-node cut ("" when the topology has none by design)
    entrypoints: list[str]
    crown_jewels: list[str]
    decoy_high_cvss: str
    seed: int
    topology: str = "single"
    planted_cut: list[str] = Field(default_factory=list)  # a known (not necessarily minimum) cut
    cve_pool: str = ""  # provenance of the planted CVE parameters (pool hash or "synthetic-fallback")
