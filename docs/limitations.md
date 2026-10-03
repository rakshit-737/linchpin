# Limitations & roadmap

## Limitations

- **The benchmark scores plans inside LINCHPIN's own model.** Disconnection and attacker cost are computed on the
  attack graph with LINCHPIN's edge costs, and the four topology families were written for this project. LINCHPIN's
  100% disconnect rate is guaranteed by max-flow / min-cut whenever the minimum cut fits the budget; the benchmark
  measures how far other planners are from that optimum, and the ablation what incomplete data costs. Neither is a
  measurement of real-world risk.
- **The identity result is designed into the families.** Only `ad` and `multi` route through cached credentials, by
  construction of the generator; `single` has no identity edge on its route. "Without identity data, 5/100" is a
  result inside the model for those families, and the pooled 37% depends on the family mix.
- **Exploit-intel costs are scored with themselves.** Planning without CVSS / EPSS / KEV loses attacker-cost gain only
  when plans are scored with those costs; scored with uniform costs, the uniform planner does better. The ablation
  does not show that exploit intel improves plans against a real attacker.
- **Different action spaces.** Score queues may only patch; LINCHPIN may also segment or rotate credentials. The best
  patch-only plan (95% [90, 97] on the 150 topologies with a cut) is the like-for-like ceiling for the queues.
- **Declared topology in the real-export case study.** Public exports come from unrelated networks, so the
  composite case-study topology is an assumption. It shows the reasoning works on real finding data, not any real
  organisation's exposure. The measured CI lab derives its topology from a scan, but it is small (5 containers on 2
  networks) and declares which network faces the internet and where the crown jewel is.
- **Version banners are not proof.** Offline CPE matching maps a detected version to every CVE whose NVD range
  contains it. Backported fixes, build options and configuration are invisible to it, so the CVE lists are an upper
  bound; platform-conditional NVD configurations are ignored.
- **Simplified attack semantics.** "Code execution" is inferred from CVSS vectors (I:H, or v2 C:P/I:P/A:P), with a
  name/severity heuristic for CVE-less checks; KEV entries are promoted to code execution. Local-privesc vulns are
  kept but grant nothing. Credential use is scored by network reachability (contract v1.3) but not blocked by it.
- **AD coverage.** AdminTo, sessions, DA membership and abusable ACEs (GenericAll/Write, WriteDacl/Owner, Owns,
  ForceChangePassword, AddMember/AddSelf, AllExtendedRights, AddAllowedToAct, ReadLAPSPassword, DCSync) are modelled.
  ADCS (ESC1-8), shadow credentials, GPO links and domain trusts are not. On the public `TESTLAB.LOCAL` collection one
  of the three abusable-ACE nodes is reachable from the declared entry points and none lies on a path to the crown
  jewel, so real-data evidence for the ACE layer is limited to parser and unit-level tests.
- **Proxy labels.** CISA KEV stands in for "exploited in the wild" in the EPSS reproduction and in M11; it is a small,
  curated subset of real exploitation, and EPSS v3 uses KEV as an input feature (likely, but not documented, for the
  v2 scores used in the reproduction).
- **Partial replication.** The reproduction covers 117,141 of the paper's ~191k CVEs (those with an NVD v3 score; the
  paper imputed v3 vectors for 73,327 v2-only CVEs) and uses KEV instead of the paper's telemetry.
- **M11 features come from today's NVD record.** Vectors and descriptions can be revised after publication; the
  temporal split is on publication date, not a replay of what was known on each CVE's first day.
- **Residual-path metric is k-capped** (k = 100/200). It saturates on dense graphs, which is why disconnect rate and
  cost gain are reported too.
- **Remediation effort weights** for the weighted cut (patch = rotate = remove ACE = 1, segmentation = 3) are
  defaults, not measured costs.
- **No cut within budget.** When the minimum cut exceeds the budget, LINCHPIN falls back to greedy set cover, which
  reaches about 83% of the optimal rise in attacker cost; the exact interdiction MILP is only a benchmark baseline.
- **Scale.** Yen's algorithm dominates the cost: about 3 s at 900 nodes and 7 s at 1,400 nodes on a laptop. The GDS
  backend runs Yen 1.4-39x faster inside Neo4j (medians across CI runs), but mirroring the graph there costs
  more than the computation saves unless the graph already lives in Neo4j.
- **Static demo.** The GitHub Pages demo holds seed-0 snapshots for budgets 1-10, and its what-if counts surviving
  *enumerated* paths instead of re-enumerating.

## Roadmap

- Use the exact interdiction MILP as the optimiser's fallback when no cut fits the budget
- ADCS / shadow-credential / GPO edges
- Credential use blocked (not only penalised) when a firewall rule set is known to be complete
- Measured per-organisation remediation costs for the weighted cut
- A larger measured lab (Active Directory in containers, more segments)
