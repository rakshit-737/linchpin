# Limitations & roadmap

## Limitations

- **Declared topology.** Public exports come from unrelated networks, so the case-study topology is an assumption.
  The results show that the reasoning works on real finding data. They do not show any real organisation's exposure.
- **Simplified attack semantics.** "Code execution" is inferred from CVSS vectors (I:H, or v2 C:P/I:P/A:P), with a
  name/severity heuristic for CVE-less checks and KEV promotion. Local-privesc vulns are kept but grant nothing.
  Credential use ignores network reachability to the target. `prerequisite_match` is fixed at 1.0.
- **AD coverage.** AdminTo, sessions, DA membership and abusable ACEs (GenericAll/Write, WriteDacl/Owner, Owns,
  ForceChangePassword, AddMember/AddSelf, AllExtendedRights, AddAllowedToAct, ReadLAPSPassword, DCSync) are modelled.
  ADCS (ESC1-8), shadow credentials, GPO links and domain trusts are not. On the public `TESTLAB.LOCAL` collection,
  none of the ACE paths is reachable from the declared entry points, so real-data evidence for the ACE layer is
  limited to parser and unit-level tests.
- **Remediation effort weights** for the weighted cut (patch = rotate = remove ACE = 1, segmentation = 3) are
  defaults, not measured costs.
- **Residual-path metric is k-capped** (k=100/200). It is informative for disconnection but not for dense graphs,
  which is why the cost gain and the disconnect rate (with 95% Wilson intervals) are reported as well.
- **Synthetic topologies** use real CVE parameters but invented hosts. Graph-shape realism is limited by the four
  families.
- **Scale.** Yen's algorithm dominates the cost. Graphs above roughly 1,500 nodes need path sampling or a Neo4j GDS
  backend (not built).
- **Static demo.** The GitHub Pages demo holds seed-0 snapshots only, and its what-if counts surviving *enumerated*
  paths instead of re-enumerating.

## Needs hardware or a live environment (documented, not built here)

- **Scanning local vulnerable containers** to produce same-network exports: Docker was not available on the build
  machine, and scanning third-party hosts is off-limits.
- **Neo4j GDS-native path queries** for large graphs: needs a running Neo4j with the GDS plugin and a large real
  graph to benchmark against. CI already runs a live Neo4j 5 round trip.

## Roadmap

- ADCS / shadow-credential / GPO edges, and credential-use reachability checks
- Neo4j GDS backend and path sampling for >1,500-node graphs
- Measured per-organisation remediation costs for the weighted cut
