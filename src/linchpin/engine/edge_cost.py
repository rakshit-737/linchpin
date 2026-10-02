"""M3: pure edge-cost function (contracts/edge_cost.md)."""
from __future__ import annotations

from pydantic import BaseModel

from linchpin.config import Config

KEV_FLOOR = 0.95  # known-exploited-in-the-wild => near-maximal exploitability


class EdgeContext(BaseModel):
    """Everything the cost of one attacker transition depends on (contracts/edge_cost.md)."""
    rel: str
    transition_class: str | None = None  # key into cfg.skill_penalty, None => 0 penalty
    cvss_base: float | None = None
    epss: float | None = None
    cvss_exploitability: float | None = None  # NVD exploitability sub-score, normalised to [0, 1]
    kev: bool = False  # listed in CISA Known Exploited Vulnerabilities
    exploitability: float | None = None  # explicit override (e.g. learned model)
    prerequisite_match: float = 1.0


def exploitability(ctx: EdgeContext) -> float:
    """Exploitability in [0, 1] of an edge.

    An explicit override (e.g. the learned model) wins; non-``ENABLES`` edges are 1.0;
    otherwise 0.6 x CVSS exploitability sub-score + 0.4 x EPSS, with whichever is known
    alone, 0.5 when neither is, and a floor of 0.95 for CISA KEV entries.
    """
    if ctx.exploitability is not None:
        return ctx.exploitability
    if ctx.rel != "ENABLES":
        return 1.0
    cv = ctx.cvss_exploitability if ctx.cvss_exploitability is not None else (
        None if ctx.cvss_base is None else ctx.cvss_base / 10.0)
    if cv is None and ctx.epss is None:
        e = 0.5
    elif ctx.epss is None:
        e = cv
    elif cv is None:
        e = ctx.epss
    else:
        e = 0.6 * cv + 0.4 * ctx.epss
    return max(e, KEV_FLOOR) if ctx.kev else e


def edge_cost(ctx: EdgeContext, cfg: Config) -> float:
    """Cost in [0, 1] of one attacker transition; lower means easier.

    ``(w1 (1 - exploitability) + w2 (1 - prerequisite_match) + w3 skill_penalty) / (w1 + w2 + w3)``,
    clamped and rounded to 6 decimals. Pure: same inputs, same output.
    """
    w = cfg.weights
    total = (w.w1 + w.w2 + w.w3) or 1.0
    skill = cfg.skill_penalty.get(ctx.transition_class, 0.0) if ctx.transition_class else 0.0
    e = min(max(exploitability(ctx), 0.0), 1.0)
    p = min(max(ctx.prerequisite_match, 0.0), 1.0)
    cost = (w.w1 * (1 - e) + w.w2 * (1 - p) + w.w3 * skill) / total
    return round(min(max(cost, 0.0), 1.0), 6)
