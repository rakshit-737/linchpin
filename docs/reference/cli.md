# CLI reference

`python -m linchpin <command>` (or the `linchpin` console script). State is kept in `.linchpin/state.json`.

| command | purpose |
| --- | --- |
| `synth --hosts N --seed S --out F` | generate a synthetic enterprise (native JSON findings) |
| `ingest [--replace] FILES... [--intel CACHE]` | parse OpenVAS / Nessus / nmap XML, SharpHound JSON dirs, overlay YAML, native JSON |
| `intel-build --data-dir D` | build the NVD + EPSS + KEV lookup cache |
| `scenario FILE.yaml` | load real exports + declared topology + intel as state |
| `build` | rebuild the attack graph |
| `paths --k K [--explain]` | ranked entry-to-crown-jewel paths |
| `fix --budget B` | budgeted remediation plan with rationale and evidence |
| `cuts [--weighted]` | chokepoints and exact min cut; `--weighted` adds the minimum-effort cut (config `fix_cost`) |
| `whatif --remove ID...` | path statistics after removing nodes |
| `node ID` | node detail with in/out edges |
| `export --format cypher/graphml --out F` | export the graph |
| `neo4j-push` | mirror into Neo4j (`NEO4J_PASSWORD` env) |

## Configuration

```yaml
weights: {w1: 0.5, w2: 0.3, w3: 0.2}
skill_penalty: {network_exploit: 0.1, cred_reuse: 0.2, client_side: 0.4, privesc: 0.3, acl_abuse: 0.25}
entrypoints: ["auto:internet_facing"]
crown_jewels: ["auto:sensitivity=high"]
exploitability_source: intel          # or: learned
fix_cost: {Vuln: 1, Credential: 1, Ace: 1, Host: 3}   # used by the weighted min cut
```
