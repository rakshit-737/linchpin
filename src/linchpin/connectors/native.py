"""Native connector: a JSON array of NormalizedFinding objects (inventory/identity exports)."""
from __future__ import annotations

import json
import logging

from pydantic import ValidationError

from linchpin.models import NormalizedFinding

log = logging.getLogger(__name__)


def parse(path: str) -> list[NormalizedFinding]:
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    return validate_many(raw)


def validate_many(raw: list[dict]) -> list[NormalizedFinding]:
    out = []
    for item in raw:
        try:
            out.append(NormalizedFinding.model_validate(item))
        except ValidationError as e:
            log.warning("dropping invalid finding: %s", e.errors()[0].get("msg"))
    return out
