# Threat Model

## System

Offline inputs (exported findings or synthetic data) go through validation into an in-memory attack graph. The engines work on that graph, and results are served over the CLI (stdout JSON) or a localhost FastAPI.

## Assets

1. **Ingested findings.** They map an organisation's weaknesses, so they are sensitive and useful to an attacker.
2. **Remediation output.** It lists which fixes matter most, so it also works as a roadmap for an attacker.
3. **Integrity of the recommendations.** Wrong advice could lead defenders to deprioritise a real risk.

## Trust boundaries

| Boundary | Crossing | Controls |
| --- | --- | --- |
| Scanner export to connector | untrusted file content | pydantic validation, drop-and-log invalid records; defusedxml recommended (TODO default) |
| User to API | HTTP on localhost | bind 127.0.0.1; no auth (TODO: token auth before any non-local use) |
| Config file | YAML | `yaml.safe_load` and pydantic validation |

## STRIDE (abridged)

| Threat | Example | Mitigation / status |
| --- | --- | --- |
| Spoofing | anyone on the host calls the API | localhost bind; auth is TODO |
| Tampering | forged findings hide a path, e.g. fake "allowed: false" reachability | provenance (`source`, `observed_at`) kept on each finding; signed or hashed input bundles are TODO |
| Repudiation | nobody can tell who ingested which data | findings keep their `source`; audit log is TODO |
| Information disclosure | state file or API output leaks the weakness map | state stays local and is gitignored; API is local-only |
| Denial of service | huge or path-explosive graph | k-shortest is capped by `k`; request-size limits are TODO |
| Elevation of privilege | XML entity expansion in the parser | stdlib expat refuses external entities; defusedxml is TODO |

## Misuse considerations

The tool could be pointed at stolen scan data to plan an attack. Its output (ranked choke points) is the same thing a defender needs, and it contains nothing that helps with exploitation: no exploit mapping, no payloads, no target interaction. That is the main reason the project is defensively scoped.

## Model-correctness risks

The cost model is heuristic. `prerequisite_match` is fixed, credential reuse ignores network reachability, and reachability is modelled per segment. Every recommendation lists its evidence path ids so an analyst can verify it. Treat the output as decision support, not ground truth.

## v0.2 additions

| Asset / entry point | Threat | Mitigation |
| --- | --- | --- |
| XML exports (OpenVAS, Nessus, nmap) | XXE, billion laughs | `defusedxml` by default; entity declarations refused without it |
| Dataset downloader | tampered sample files | commit-pinned URLs plus SHA-256 verification; HTTPS only; reports only, never binaries |
| Web UI (`/ui`) | CDN compromise, XSS from finding strings | Cytoscape pinned with SRI; all finding text HTML-escaped before insertion |
| `/demo/load` scenario path | reading arbitrary server files | parsed only as scenario YAML plus known export formats; API binds to localhost and must not be exposed |
| Neo4j mirror | credential leakage | password only via `NEO4J_PASSWORD`, never in config; the compose file binds to localhost |
