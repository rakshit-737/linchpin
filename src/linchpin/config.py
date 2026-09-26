from __future__ import annotations

from pathlib import Path

import yaml
from pydantic import BaseModel, Field


class Weights(BaseModel):
    w1: float = 0.5
    w2: float = 0.3
    w3: float = 0.2


class Config(BaseModel):
    weights: Weights = Field(default_factory=Weights)
    skill_penalty: dict[str, float] = Field(
        default_factory=lambda: {"network_exploit": 0.1, "cred_reuse": 0.2, "client_side": 0.4, "privesc": 0.3}
    )
    entrypoints: list[str] = Field(default_factory=lambda: ["auto:internet_facing"])
    crown_jewels: list[str] = Field(default_factory=lambda: ["auto:sensitivity=high"])
    k_shortest: int = 10
    # "intel": CVSS sub-score + EPSS + KEV floor (default); "learned": M11 model score when present
    exploitability_source: str = "intel"
    neo4j: dict[str, str] = Field(default_factory=lambda: {"uri": "bolt://localhost:7687", "user": "neo4j"})


def load_config(path: str | Path | None = None) -> Config:
    if path is None or not Path(path).exists():
        return Config()
    return Config.model_validate(yaml.safe_load(Path(path).read_text()) or {})
