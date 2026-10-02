# ADR 0001: Exact minimum cut first, greedy set cover as fallback

**Status:** accepted (v0.2); updated with prior work and measurements in v1.1

## Context
The v0.1 optimizer was greedy weighted set cover over the k-shortest attack paths. On topologies with parallel pivots
(`multi` family), greedy needed 1.22x the true minimum number of fixes on average and missed full disconnection
within budget in 6% of seeds (current benchmark). On flat networks (`none`) it needed 1.29x.

Choosing a minimum set of fixes that disconnects an attack graph is classical: minimum-cost network hardening
(Noel et al., ACSAC 2003; Wang, Noel & Jajodia, Computer Communications 2006; Albanese, Jajodia & Noel, DSN 2012),
identity-graph hardening (Dunagan et al., Heat-ray, SOSP 2009) and budgeted edge blocking on Active Directory graphs
(Guo et al., AAAI 2022 and 2023). A vertex min cut is max-flow / min-cut (Ford & Fulkerson 1956). LINCHPIN does not
claim a new algorithm here; see [Datasets & references](../datasets.md#references).

## Decision
Compute the exact minimum vertex cut over *remediable* nodes (Vuln, Credential, Ace, non-endpoint Host) with a
vertex-split max-flow (`engine/cuts.py`). Structural nodes get infinite capacity.
- If the greedy plan already disconnects everything using at most as many fixes as the minimum cut, keep it, because
  its ordering reflects path coverage.
- Otherwise, if the cut fits the budget, re-run greedy restricted to the cut nodes. That keeps coverage ordering,
  rationales and evidence, and it provably disconnects with the fewest fixes.
- Otherwise fall back to greedy, which maximises paths broken.

Chokepoints are reported separately from the dominator tree of a virtual source/sink.

## Consequences
- `multi` goes from 94% to 100% disconnection at budget 3, with no change elsewhere (pooled 98% -> 100%, exact
  McNemar p = 0.25 over 150 topologies: the cut matters for *how many* fixes, 1.22x vs 1.00x, more than for whether
  3 suffice).
- When no cut fits the budget, the greedy fallback reaches 0.83 [0.77, 0.88] of the best achievable rise in the
  attacker's cheapest-path cost, measured against the exact interdiction MILP of Israeli & Wood (2002). Using that
  MILP as the fallback is on the roadmap.
- One extra max-flow per request; Yen enumeration still dominates.
