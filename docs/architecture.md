# Architecture

## Overview

The same diagram is in the README.

```mermaid
flowchart TB
  EX["Exports: OpenVAS, Nessus, nmap, SharpHound, topology YAML"] --> CON["Connectors to NormalizedFinding"]
  INTEL["Public intel: NVD, FIRST EPSS, CISA KEV"] --> ENR["Version-to-CVE matching and enrichment"]
  CON --> ENR --> G["GraphStore: attack graph with edge costs"]
  G --> P["Yen k-shortest paths"]
  G --> CUT["Chokepoints and exact min cut"]
  P --> OPT["Optimizer: exact cut, else greedy set cover"]
  CUT --> OPT --> EXP["Templated rationale and evidence"]
  EXP --> OUT["CLI, FastAPI, Cytoscape explorer"]
  G -.-> N4[("Neo4j mirror and GDS")]
```

## Inputs to findings

```mermaid
flowchart TB
  subgraph Exports["Offline exports"]
    OV["OpenVAS / Greenbone XML"]
    NE["Nessus .nessus"]
    NM["nmap XML (-sV, vulners)"]
    BH["SharpHound JSON"]
    INV["topology / inventory YAML"]
  end
  subgraph Intel["Public exploit intel (local files)"]
    NVD["NVD CVE 2.0 feeds"]
    EPSS["FIRST EPSS"]
    KEV["CISA KEV"]
  end
  Exports --> C["connectors: NormalizedFinding, host aliasing"]
  NVD --> CPE["CPE index: NVD version ranges"]
  NVD --> I["CveIntel cache"]
  EPSS --> I
  KEV --> I
  C --> M["match-cpe: versions to CVEs"]
  CPE --> M
  M --> E["enrich: CVSS, EPSS, KEV"]
  I --> E
  ML["M11 learned exploit model (optional)"] -.-> E
```

## Engine and outputs

```mermaid
flowchart TB
  F["NormalizedFinding list"] --> G["GraphStore.build_attack_graph"]
  COST["edge_cost: pure function"] --> G
  G --> P["paths: Yen k-shortest on the pruned subgraph"]
  G --> CUT["cuts: dominators and vertex max-flow"]
  G --> INT["interdiction: Israeli and Wood MILP, greedy (for comparison)"]
  P --> O["optimizer.recommend"]
  CUT --> O
  O --> X["explain: templates, no LLM"]
  X --> CLI["CLI (JSON)"]
  X --> API["FastAPI (localhost)"]
  API --> UI["Cytoscape explorer and what-if"]
  G -.-> N4[("Neo4j: push / pull, .cypher export, GDS Yen")]
```

## Graph model

Edges point in the attacker's direction of travel, so a path is a walk the attacker takes.

```mermaid
flowchart TB
  INT["Internet"] -- "CAN_REACH" --> SVC["Service"]
  SVC -- "HAS_VULN" --> V["Vuln"]
  V -- "ENABLES" --> PR["Privilege (local admin)"]
  PR -- "LEADS_TO" --> H["Host"]
  H -- "CAN_REACH" --> SVC
  H -- "STORED_ON" --> CR["Credential"]
  CR -- "GRANTS" --> PR
  CR -- "HAS_ACE" --> ACE["Ace (AD ACL entry)"]
  ACE -- "ABUSES" --> CR
  ACE -- "ABUSES" --> PR
  ACE -- "ABUSES" --> DS["DataStore (crown jewel)"]
  H -- "HOLDS" --> DS
```

Remediable nodes are `Vuln` (patch or upgrade), `Credential` (rotate, clear cached copies), `Ace` (remove the ACL
entry) and non-entry, non-crown `Host` (segmentation rule). The frozen taxonomy lives in
[`contracts/graph_model.md`](https://github.com/rakshit-737/linchpin/blob/main/contracts/graph_model.md);
v1.2 added `Ace`, `HAS_ACE` and `ABUSES`, v1.3 the network-reachability prerequisite of credential use.

## Modules

| Module | Path | Notes |
| --- | --- | --- |
| M1 connectors | `src/linchpin/connectors/` | OpenVAS, Nessus, nmap (+ `vulners`), BloodHound v5/v6 incl. ACEs, inventory overlay, native JSON |
| intel | `src/linchpin/intel/` | NVD 2.0 / EPSS / KEV parsers, 379k-CVE cache, enrichment, offline CPE version matching |
| M2 GraphStore | `src/linchpin/graph/` | NetworkX store; Neo4j push/pull, `.cypher` export, GDS Yen |
| M3 edge cost | `src/linchpin/engine/edge_cost.py` | frozen formula: CVSS exploitability sub-score, EPSS, KEV floor, credential reachability |
| M4 paths | `src/linchpin/engine/paths.py` | Yen k-shortest, kill-chain stages, criticality |
| cuts | `src/linchpin/engine/cuts.py` | dominator chokepoints; min vertex cut by count or by effort |
| interdiction | `src/linchpin/engine/interdiction.py` | exact budgeted interdiction MILP and greedy interdiction (benchmark baselines) |
| M5 optimizer | `src/linchpin/engine/optimizer.py` | exact cut when within budget, else greedy set cover |
| M6 explain | `src/linchpin/engine/explain.py` | deterministic templates, no LLM |
| M7 API / M10 UI | `src/linchpin/api/` | FastAPI with host allow-list and limits; Cytoscape.js explorer (also the static demo) |
| M8 CLI | `src/linchpin/cli.py` | `ingest`, `scenario`, `paths`, `fix`, `cuts`, `whatif`, `export`, `serve`, ... |
| M9 synth | `src/linchpin/synth/` | four topology families using real CVE parameters |
| M11 ML | `src/linchpin/ml/exploitability.py` | KEV-membership model, labels known at the cutoff, exploitation-status text masked |
