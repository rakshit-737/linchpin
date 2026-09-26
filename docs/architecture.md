# Architecture

```mermaid
flowchart LR
  subgraph Exports["Offline exports"]
    OV["OpenVAS XML"]
    NE["Nessus .nessus"]
    NM["nmap XML + vulners"]
    BH["SharpHound JSON"]
    INV["topology / inventory YAML"]
  end
  subgraph Intel["Public exploit intel"]
    NVD["NVD CVE 2.0"]
    EPSS["FIRST EPSS"]
    KEV["CISA KEV"]
  end
  OV --> C["connectors (NormalizedFinding)"]
  NE --> C
  NM --> C
  BH --> C
  INV --> C
  NVD --> I["CveIntel cache"]
  EPSS --> I
  KEV --> I
  I --> E["enrich"]
  ML["M11 learned exploit model"] -.-> E
  C --> SC["scenario loader + host aliasing"] --> E --> G["GraphStore (NetworkX)"]
  G -.-> N4[("Neo4j mirror")]
  COST["edge_cost (pure function)"] --> G
  G --> P["paths: Yen k-shortest"]
  G --> CUT["cuts: dominators + (weighted) min cut"]
  P --> O["optimizer: exact cut / greedy set cover"]
  CUT --> O --> X["explain: templates"]
  X --> CLI["CLI"]
  X --> API["FastAPI"] --> UI["Cytoscape UI + what-if"]
```

## Graph model

Edges point in the attacker's direction of travel, so a path is a walk the attacker takes.

```mermaid
flowchart LR
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

Remediable nodes are `Vuln` (patch), `Credential` (rotate, clear cached copies), `Ace` (remove the ACL
entry) and non-entry, non-crown `Host` (segmentation rule). The frozen taxonomy lives in
[`contracts/graph_model.md`](https://github.com/rakshit-737/linchpin/blob/main/contracts/graph_model.md);
v1.2 added `Ace`, `HAS_ACE` and `ABUSES`.

## Modules

| Module | Path | Notes |
| --- | --- | --- |
| M1 connectors | `src/linchpin/connectors/` | OpenVAS, Nessus, nmap (+ `vulners`), BloodHound v5/v6 incl. ACEs, inventory overlay, native JSON |
| intel | `src/linchpin/intel/` | NVD 2.0 / EPSS / KEV parsers, 379k-CVE cache, enrichment |
| M2 GraphStore | `src/linchpin/graph/` | NetworkX store; Neo4j push/pull and `.cypher` export |
| M3 edge cost | `src/linchpin/engine/edge_cost.py` | frozen formula, CVSS exploitability sub-score, KEV floor |
| M4 paths | `src/linchpin/engine/paths.py` | Yen k-shortest, kill-chain stages, criticality |
| cuts | `src/linchpin/engine/cuts.py` | dominator chokepoints; min vertex cut by count or by effort |
| M5 optimizer | `src/linchpin/engine/optimizer.py` | exact cut when within budget, else greedy set cover |
| M6 explain | `src/linchpin/engine/explain.py` | deterministic templates, no LLM |
| M7 API / M10 UI | `src/linchpin/api/` | FastAPI + Cytoscape.js explorer (also built as a static demo) |
| M8 CLI | `src/linchpin/cli.py` | `ingest`, `scenario`, `paths`, `fix`, `cuts`, `whatif`, `export`, ... |
| M9 synth | `src/linchpin/synth/` | four topology families using real CVE parameters |
| M11 ML | `src/linchpin/ml/exploitability.py` | KEV-membership model on a temporal split |
