# Edge-cost model (FROZEN)

    cost(edge) = w1 * (1 - exploitability) + w2 * (1 - prerequisite_match) + w3 * skill_penalty

Lower = easier for the attacker. Result is clamped to [0, 1] and weights are normalised so they sum to 1.

| term | source |
| --- | --- |
| exploitability | `ENABLES` (vuln): 0.6 * cv + 0.4 * epss, where cv is the NVD CVSS *exploitability sub-score* normalised to [0,1] when known (v3: /3.9, v2: /10), else cvss_base/10 (cv alone if EPSS missing; epss alone if CVSS missing; 0.5 if both missing). If the CVE is in CISA KEV, exploitability = max(value, 0.95). `GRANTS` (valid credential), `CAN_REACH`, `LEADS_TO`, `STORED_ON`: 1.0 |
| prerequisite_match | 1.0 by default (the MVP does not model partial prerequisites yet) |
| skill_penalty | per transition class from config: network_exploit, cred_reuse, client_side, privesc; structural edges (LEADS_TO, HOLDS) use 0 |

Defaults: w1=0.5, w2=0.3, w3=0.2. Implementation: `src/linchpin/engine/edge_cost.py` (pure function).
The learned variant (M11, `src/linchpin/ml/exploitability.py`) only changes how `exploitability` is sourced (passed as an explicit override); the formula shape is unchanged.

Additive, backwards-compatible extension (v1.1): `cvss_exploitability` and `kev` inputs. With neither set, results are identical to v1.0.
