"""Native connector: a JSON array of NormalizedFinding objects (inventory/identity exports)."""
from __future__ import annotations

import json
import logging

from pydantic import ValidationError

from linchpin.models import NormalizedFinding, detail_problem

log = logging.getLogger(__name__)


def parse(path: str) -> list[NormalizedFinding]:
    """Read a JSON array of findings; invalid records are dropped and logged."""
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    if not isinstance(raw, list):
        raise ValueError(f"{path}: expected a JSON array of findings")
    return validate_many(raw)


def validate_many(raw: list[dict]) -> list[NormalizedFinding]:
    """Schema-validate each record and check its kind-specific ``detail``; drop and log the rest."""
    out = []
    for item in raw:
        try:
            f = NormalizedFinding.model_validate(item)
        except ValidationError as e:
            log.warning("dropping invalid finding: %s", e.errors()[0].get("msg"))
            continue
        problem = detail_problem(f)
        if problem:
            log.warning("dropping finding %s: %s", f.finding_id, problem)
            continue
        out.append(f)
    return out
