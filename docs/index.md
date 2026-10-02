# LINCHPIN

**Read-only attack-path reasoning: find the few fixes that cut every route to the crown jewels, using scanner, identity and exploit-intel data.**

!!! abstract "Contribution, in one sentence"
    LINCHPIN's contribution is evidence, not a new cut algorithm: adding identity (BloodHound) data to the
    scanner graph lifts the 3-fix disconnect rate from **37% [29, 45]** to **100% [97.5, 100]** of 150 seeded
    topologies (KEV-then-EPSS queue: **3% [1, 7]**). Segmentation and exploit-intel costs change how many fixes
    are needed (flat-network view: 1.82x the minimum on `single`) and the attacker-cost gain, not the disconnect rate.

The minimum vertex cut itself is classical (minimum-cost network hardening has been studied since Noel et al. 2003
and Wang, Noel & Jajodia 2006); what LINCHPIN adds is the fusion of real exports, evidence-carrying fix plans, and an
open, seeded evaluation with an ablation, published-method baselines and a measured lab. See
[Evaluation](evaluation.md) for methods and every number.

| evidence | result (95% intervals) | where |
| --- | --- | --- |
| Ablation, 150 topologies, paired | fused data 100% [97.5, 100]; without identity data 37% [29, 45] (McNemar p < 1e-4); 25% / 50% of identity findings dropped: 95% / 90%; identity data only 18%; no graph (KEV→EPSS) 3% | [ablation](evaluation.md#ablation) |
| Published planners | exact budgeted interdiction MILP (Israeli & Wood 2002) also 100%; Guo et al.-style greedy interdiction 97% [92, 99]; CVSS / EPSS / KEV queues restricted to on-path vulns 10% [6, 16] / 9% [6, 15] | [benchmark](evaluation.md#synthetic-benchmark) |
| Measured lab (CI, internal Docker networks) | one 5-service lab: upgrading Tomcat 9.0.30 (1 fix) cuts the database off; betweenness, greedy and MILP also need 1; EPSS- and KEV-first 2, CVSS-first 3 | [lab scan](evaluation.md#measured-case-study-ci-lab-scan) |
| Published result reproduced | Jacobs et al. (2023), EPSS v2 with public KEV labels: effort and coverage within ~2-8 points (CVSS 7+ coverage 89.6% vs 82.1%); efficiency does not reproduce (1.6% vs 8.9%, KEV is a sparser label) | [reproduction](evaluation.md#reproduction-epss-vs-cvss-jacobs-et-al-2023) |

## Try it in 60 seconds

=== "In the browser"

    [Open the path explorer](demo/index.html){ .md-button .md-button--primary } - runs from pre-computed snapshots,
    nothing leaves the page.

=== "Command line (uv)"

    ```bash
    uvx --from git+https://github.com/rakshit-737/linchpin linchpin synth --out lab.json   # seeded topology, real CVE parameters
    uvx --from git+https://github.com/rakshit-737/linchpin linchpin ingest --replace lab.json
    uvx --from git+https://github.com/rakshit-737/linchpin linchpin fix --budget 3
    # -> "add segmentation rule isolating jump-01 ... breaks 100/100 enumerated attack paths to ds:customer-db"
    ```

    37 s from an empty uv cache on a home connection (pip into a fresh venv: about 70 s).

=== "Web UI (Docker)"

    ```bash
    git clone https://github.com/rakshit-737/linchpin && cd linchpin
    docker build -t linchpin . && docker run --rm -p 127.0.0.1:8000:8000 linchpin   # http://127.0.0.1:8000/ui
    ```

![path explorer](img/ui.png)
*The explorer on the real-export case study: the top fix (rotate the cached Domain-Admin credential) is selected and
every attack path it breaks is highlighted.*

## What it does

LINCHPIN reads exports that were **already collected** (OpenVAS, Nessus and nmap reports, SharpHound/BloodHound JSON,
and a topology/inventory overlay), maps detected versions to CVEs offline, enriches them with NVD CVSS vectors,
FIRST EPSS and CISA KEV, and builds a heterogeneous attack graph. From that graph it:

1. enumerates and ranks entry-to-crown-jewel attack paths (Yen's k-shortest paths),
2. finds **chokepoints** (dominators) and the **exact minimum remediation cut** (vertex max-flow), optionally weighted
   by remediation effort,
3. recommends an ordered, budgeted set of fixes (patch or upgrade, rotate a credential, remove an abusable AD ACL, add
   a segmentation rule), each with a templated rationale and the ids of the attack paths it breaks,
4. serves this through a CLI, a FastAPI service, a Cytoscape.js path explorer with what-if analysis, and an optional
   Neo4j mirror with a Graph Data Science backend.

**Safety property:** LINCHPIN sends no packets and only parses files. It cannot exploit anything. See
[Security](security.md) and the [Threat model](threat-model.md).

## Headline results

| evaluation | result |
| --- | --- |
| Synthetic benchmark (4 families x 50 seeds, real CVE parameters, budget 3) | cuts the crown jewel off in 100% of the 150 topologies where a 3-fix cut exists; CVSS / EPSS / KEV queues 3-4%, on-path variants 9-10%, betweenness 39%; on average 69% [63, 76] of the enumerated attack paths are broken by LINCHPIN's 3 fixes but not by CVSS-first's |
| No cut within budget (`none` family) | LINCHPIN reaches 0.83 [0.77, 0.88] of the optimal rise in the attacker's cheapest-path cost (exact MILP), KEV→EPSS 0.15 |
| Real-export case study (declared topology) | one credential rotation cuts the domain controller off; enriched CVSS / EPSS / KEV queues with 3 fixes do not |
| Learned exploitability (temporal split, leak-free) | ROC-AUC 0.836 vs 0.754 for CVSS base score; average precision 0.028 vs 0.011 |
| Neo4j GDS cross-check (CI) | identical k-shortest paths on up to 238,665 relationships; Yen 4-31x faster in GDS than in NetworkX, but mirroring the graph into Neo4j takes 8-22 s |

Details, intervals and caveats: [Evaluation](evaluation.md). Every command and runtime: [Reproduce](reproduce.md).
