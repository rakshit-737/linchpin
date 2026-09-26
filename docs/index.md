# LINCHPIN

**Read-only attack-path reasoning: find the few fixes that cut every route to the crown jewels, using scanner, identity and exploit-intel data.**

> A CVSS-10 on an unreachable host is correctly deprioritised. A cached Domain-Admin hash that every attack path needs is ranked #1.

LINCHPIN reads exports that were **already collected** (OpenVAS, Nessus and nmap reports, SharpHound/BloodHound JSON, and a topology/inventory overlay), enriches them with NVD CVSS vectors, FIRST EPSS and CISA KEV, and builds a heterogeneous attack graph. From that graph it:

1. enumerates and ranks entry-to-crown-jewel attack paths (Yen's k-shortest paths),
2. finds **chokepoints** (dominators) and the **exact minimum remediation cut** (vertex max-flow), optionally weighted by remediation effort,
3. recommends an ordered, budgeted set of fixes (patch, rotate a credential, remove an abusable AD ACL, add a segmentation rule), each with a templated rationale and the ids of the attack paths it breaks,
4. serves this through a CLI, a FastAPI service, a Cytoscape.js path explorer with what-if analysis, and an optional Neo4j mirror.

**Safety property:** LINCHPIN sends no packets and only parses files. It cannot exploit anything. See [Security](security.md) and the [Threat model](threat-model.md).

[Try the static demo](demo/index.html){ .md-button .md-button--primary } [Getting started](getting-started.md){ .md-button }

![path explorer](img/ui.png)

## Headline results

| | |
| --- | --- |
| Real-export case study | one credential rotation cuts the domain controller off; CVSS-, EPSS- and KEV-sorted queues with 3 fixes cut nothing |
| Synthetic benchmark (4 families x 50 seeds, real CVE parameters) | LINCHPIN disconnects 100% of single / AD / multi-pivot topologies with 3 fixes; score-sorted baselines 0-14% |
| Learned exploitability (temporal split, KEV label) | ROC-AUC 0.86 vs 0.75 for CVSS base score |

Details, confidence intervals and caveats: [Benchmarks & results](benchmarks.md).
