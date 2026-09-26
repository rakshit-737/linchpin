# ADR 0001: Exact minimum cut first, greedy set cover as fallback

**Status:** accepted (v0.2)

## Context
The v0.1 optimizer was greedy weighted set cover over the k-shortest attack paths. On topologies with parallel pivots (`multi` family), greedy needed 1.17x the true minimum number of fixes on average and missed full disconnection within budget in 4% of seeds. On flat networks (`none`) it needed 1.34x.

## Decision
Compute the exact minimum vertex cut over *remediable* nodes (Vuln, Credential, non-endpoint Host) with a vertex-split max-flow (`engine/cuts.py`). Structural nodes get infinite capacity.
- If the greedy plan already disconnects everything using at most as many fixes as the minimum cut, keep it, because its ordering reflects path coverage.
- Otherwise, if the cut fits the budget, re-run greedy restricted to the cut nodes. That keeps coverage ordering, rationales and evidence, and it provably disconnects with the fewest fixes.
- Otherwise fall back to greedy, which maximises paths broken and the attacker-cost increase.

Chokepoints are reported separately from the dominator tree of a virtual source/sink.

## Consequences
- The `multi` family goes from 96% to 100% disconnection at budget 3, with no change elsewhere.
- One extra max-flow per request. That is under 1.5 s at 900 nodes; Yen enumeration still dominates.
- The cut is unweighted (fix count). Weighted remediation effort is on the roadmap.
