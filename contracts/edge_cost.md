# Edge-cost model (FROZEN)

    cost(edge) = w1 * (1 - exploitability) + w2 * (1 - prerequisite_match) + w3 * skill_penalty

Lower = easier for the attacker. Result is clamped to [0, 1] and weights are normalised so they sum to 1.

| term | source |
| --- | --- |
| exploitability | `ENABLES` (vuln): 0.6 * cvss/10 + 0.4 * epss (cvss/10 alone if EPSS missing; 0.5 if both missing). `GRANTS` (valid credential), `CAN_REACH`, `LEADS_TO`, `STORED_ON`: 1.0 |
| prerequisite_match | 1.0 by default (the MVP does not model partial prerequisites yet) |
| skill_penalty | per transition class from config: network_exploit, cred_reuse, client_side, privesc; structural edges (LEADS_TO, HOLDS) use 0 |

Defaults: w1=0.5, w2=0.3, w3=0.2. Implementation: `src/linchpin/engine/edge_cost.py` (pure function).
The optional learned variant (M11, not built) would only change how `exploitability` is sourced.
