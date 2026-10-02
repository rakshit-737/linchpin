# Design notes

## Attack graph

`Host -RUNS-> Service -HAS_VULN-> Vuln -ENABLES-> Privilege -LEADS_TO-> Host`, with
`Host -STORED_ON-> Credential -GRANTS-> Privilege`, `Host|Internet -CAN_REACH-> Service` from segment
reachability rules, and `Host -HOLDS-> DataStore` for crown jewels. The taxonomy is frozen in
`contracts/graph_model.md`.

* **Which vulns grant a privilege?** Only those whose CVSS vector implies code execution: network or adjacent access
  and integrity High (v3) / Complete (v2), or v2 `C:P/I:P/A:P`. CVE-less checks use a name/severity heuristic
  (backdoor, default credentials, command execution, severity >= 9). KEV entries are always promoted. Unknown vectors
  (synthetic data) are treated as code execution.
* **Edge cost:** `w1 (1 - exploitability) + w2 (1 - prerequisite_match) + w3 skill`. Exploitability is
  `0.6 cvss_expl + 0.4 epss`, where `cvss_expl` is the NVD exploitability sub-score normalised to [0, 1], falling
  back to base/10. KEV entries are floored at 0.95. The M11 score can replace it (`exploitability_source: learned`).
  Since contract v1.3, `prerequisite_match` is 0.5 for credential use whose target is not reachable from any segment
  where the credential is recoverable.
* **Identity layer (BloodHound):** local Administrators membership (nested groups expanded) and DA/EA/BUILTIN
  Administrators produce `AdminTo`. Interactive, privileged and registry sessions produce a credential cached on that
  computer, valid wherever the user is admin. Domain controllers hold an `ntds` crown jewel.
* **Versions to CVEs:** a service seen with a product version is matched against NVD's `cpeMatch` version ranges
  offline (`intel/cpe.py`); the resulting vuln stands for "upgrade this software", and its edge uses the CVE an
  attacker would pick (code execution by vector, then KEV, then EPSS).

## Optimisation

See ADR 0001. Candidates are Vuln (patch / upgrade), Credential (rotate / purge cached copies), Ace (remove the ACL
entry) and non-endpoint Host (segmentation). The plan uses the exact vertex min cut when it fits the budget and the
greedy path set cover otherwise. The benchmark metrics are disconnect rate, k-capped residual paths, the attacker's
cheapest-path cost gain and its share of the optimum from the interdiction MILP.

## Determinism

Same input, same output: findings are processed in `finding_id` order, path ties are broken in graph insertion order
(independent of `PYTHONHASHSEED`, regression-tested), the synthetic generator and every benchmark are seeded, and the
CPE index is written as byte-reproducible gzip.

## Performance

Yen k-shortest paths dominate the cost. Paths are enumerated on the subgraph that is both reachable from an entry point
and able to reach a crown jewel, reachability checks walk adjacency without copying the graph, and the API refuses a
build whose projected edge count exceeds `LINCHPIN_MAX_EDGES` before doing the quadratic same-segment pass.
