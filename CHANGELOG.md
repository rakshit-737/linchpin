# Changelog

## 0.2.0 (2026-09-26): real data

### Added
- **Connectors:** OpenVAS/Greenbone XML, Nessus `.nessus`, nmap `vulners` CVEs, SharpHound/BloodHound v5/v6 JSON (admin rights with nested groups, sessions, DA/DC), topology/inventory overlay YAML. Format auto-detection and `defusedxml`.
- **Exploit intel:** NVD CVE 2.0, FIRST EPSS and CISA KEV parsers; a 379k-CVE lookup cache (`linchpin intel-build`); finding enrichment.
- **Scenario loader:** real exports, declared topology, host aliasing and intel in one YAML (`scenarios/composite_lab.yaml`).
- **Engine:** exact minimum remediation cut (vertex max-flow) and chokepoints (dominators); the optimizer uses the exact cut when it fits the budget.
- **M11:** learned exploit-likelihood model (KEV label, temporal split). Opt in with `exploitability_source: learned`.
- **Neo4j adapter:** push/pull mirror using the frozen taxonomy, `.cypher` export, and a live CI job.
- **Web UI:** Cytoscape.js path explorer, evidence highlighting and what-if, served at `/ui`.
- **Benchmarks:** four topology families (single / multi / none / AD) using a real CVE pool, six baselines, the real-export case study and a scaling run.
- **CLI:** `scenario`, `intel-build`, `cuts`, `export`, `neo4j-push`; `ingest --intel`.
- Checksummed dataset downloader; LICENSE, CONTRIBUTING, ADRs.

### Changed (additive to the frozen contracts)
- Edge cost prefers the NVD CVSS *exploitability sub-score* and floors exploitability at 0.95 for KEV entries.
- A vuln grants a privilege only if its CVSS vector (or a conservative heuristic) implies code execution.
- About 4x faster optimiser: Yen runs on the entry-to-crown subgraph, and reachability no longer copies the graph.

## 0.1.0

- MVP: frozen contracts, in-memory GraphStore, edge cost, Yen paths, greedy optimizer, templated explanations, FastAPI, CLI, synthetic generator and benchmark.
