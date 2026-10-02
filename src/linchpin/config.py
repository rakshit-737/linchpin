"""Configuration model (contracts/config.schema.json) and its YAML loader."""
from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class Weights(BaseModel):
    """Edge-cost weights of contracts/edge_cost.md (normalised to sum to 1 when used)."""

    w1: float = 0.5  # 1 - exploitability
    w2: float = 0.3  # 1 - prerequisite_match
    w3: float = 0.2  # skill penalty of the transition class


class Config(BaseModel):
    """Everything that shapes the attack graph and the plan; every field has a default."""

    weights: Weights = Field(default_factory=Weights)
    skill_penalty: dict[str, float] = Field(
        default_factory=lambda: {"network_exploit": 0.1, "cred_reuse": 0.2, "client_side": 0.4, "privesc": 0.3,
                                 "acl_abuse": 0.25}
    )
    entrypoints: list[str] = Field(default_factory=lambda: ["auto:internet_facing"])
    crown_jewels: list[str] = Field(default_factory=lambda: ["auto:sensitivity=high"])
    k_shortest: int = 10
    # "intel": CVSS sub-score + EPSS + KEV floor (default); "learned": M11 model score when present
    exploitability_source: str = "intel"
    # Contract v1.3: credential use whose target host is not network-reachable from where the
    # credential is recoverable gets prerequisite_match = prerequisite_penalty (1.0 otherwise).
    credential_reachability: bool = True
    prerequisite_penalty: float = Field(0.5, ge=0.0, le=1.0)
    # Relative effort per remediation type, used by the weighted (cost-aware) min cut:
    # patching / rotating / removing an ACE is cheap, a new segmentation rule is expensive.
    fix_cost: dict[str, float] = Field(
        default_factory=lambda: {"Vuln": 1.0, "Credential": 1.0, "Ace": 1.0, "Host": 3.0})
    neo4j: dict[str, str] = Field(default_factory=lambda: {"uri": "bolt://localhost:7687", "user": "neo4j"})


def load_config(path: str | Path | None = None) -> Config:
    """Read a YAML config (missing file or ``None`` -> defaults); unknown keys are ignored."""
    if path is None or not Path(path).exists():
        return Config()
    return Config.model_validate(yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {})
