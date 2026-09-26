# Design notes

## Attack graph

`Host -RUNS-> Service -HAS_VULN-> Vuln -ENABLES-> Privilege -LEADS_TO-> Host`, with
`Host -STORED_ON-> Credential -GRANTS-> Privilege`, `Host|Internet -CAN_REACH-> Service` from segment
reachability rules, and `Host -HOLDS-> DataStore` for crown jewels. The taxonomy is frozen in
`contracts/graph_model.md`.

* **Which vulns grant a privilege?** Only those whose CVSS vector implies code execution: network or
  adjacent access and integrity High (v3) / Complete (v2), or v2 `C:P/I:P/A:P`. CVE-less checks use a
  name/severity heuristic (backdoor, default credentials, command execution, severity >= 9). KEV
  entries are always promoted. Unknown vectors (synthetic data) are treated as code execution.
* **Edge cost:** `w1(1-exploitability) + w2(1-prereq) + w3*skill`. Exploitability is
  `0.6*cvss_expl + 0.4*epss`, where `cvss_expl` is the NVD exploitability sub-score normalised to
  [0,1], falling back to base/10. KEV entries are floored at 0.95. The M11 score can replace it
  (`exploitability_source: learned`).
* **Identity layer (BloodHound):** local Administrators membership (nested groups expanded) and
  DA/EA/BUILTIN Administrators produce `AdminTo`. Interactive, privileged and registry sessions
  produce a credential cached on that computer, valid wherever the user is admin. Domain controllers
  hold an `ntds` crown jewel.

## Optimisation

See ADR 0001. Candidates are Vuln (patch), Credential (rotate / purge cached copies) and non-endpoint
Host (segmentation). The benchmark metrics are disconnect rate, k-capped residual paths, and the
attacker's cheapest-path cost gain.

## Performance

Yen k-shortest paths dominate the cost. Paths are enumerated on the subgraph that is both reachable
from an entrypoint and able to reach a crown jewel, and reachability checks walk adjacency without
copying the graph.
