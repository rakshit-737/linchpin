"""Frozen contract models (see contracts/)."""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field

Kind = Literal["cve", "service", "credential", "acl", "config", "reachability"]
Stage = Literal["recon", "exploit", "privesc", "lateral", "objective"]


def make_finding_id(host_id: str, kind: str, key: str) -> str:
    return hashlib.sha256(f"{host_id}|{kind}|{key}".encode()).hexdigest()[:16]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class NormalizedFinding(BaseModel):
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


class AttackPath(BaseModel):
    path_id: str
    nodes: list[str]
    edges: list[str]
    total_cost: float
    stages: list[Stage]
    crown_jewel: str


class Remediation(BaseModel):
    target_node: str
    action: str
    paths_broken: int
    paths_total: int
    residual_paths: int
    coverage_pct: float
    rationale: str
    evidence: list[str]


class BuildStats(BaseModel):
    nodes: int
    edges: int
    build_ms: float


class NodeDetail(BaseModel):
    id: str
    label: str
    props: dict[str, Any]
    inbound: list[dict[str, Any]]
    outbound: list[dict[str, Any]]


class PathStats(BaseModel):
    removed: list[str]
    paths_before: int
    paths_after: int
    reachable_crown_jewels_before: list[str]
    reachable_crown_jewels_after: list[str]
    min_cost_before: float | None
    min_cost_after: float | None


class GroundTruth(BaseModel):
    linchpin: str
    entrypoints: list[str]
    crown_jewels: list[str]
    decoy_high_cvss: str
    seed: int
