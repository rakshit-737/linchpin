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
| Scanner export to connector | untrusted file content | pydantic validation, drop-and-log invalid records; `defusedxml` parsing (a hard dependency since 0.2.0) |
| User to API | HTTP on localhost | bind 127.0.0.1; `Host` allow-list (`LINCHPIN_ALLOWED_HOSTS`) against DNS rebinding; JSON bodies only (no simple-request CSRF); size and work limits; no auth (token auth is needed before any non-local use) |
| Config file | YAML | `yaml.safe_load` and pydantic validation |

## STRIDE (abridged)

| Threat | Example | Mitigation / status |
| --- | --- | --- |
| Spoofing | anyone on the host, or a browser page via DNS rebinding, calls the API | localhost bind; `Host` header allow-list (400 otherwise); auth is still TODO |
| Tampering | forged findings hide a path, e.g. fake "allowed: false" reachability | provenance (`source`, `observed_at`) kept on each finding; signed or hashed input bundles are TODO |
| Repudiation | nobody can tell who ingested which data | findings keep their `source`; audit log is TODO |
| Information disclosure | state file or API output leaks the weakness map | state stays local and is gitignored; API is local-only |
| Denial of service | huge body, quadratic graph build, path explosion | 413 above `LINCHPIN_MAX_BODY_MB` (25, also for streamed bodies), above `LINCHPIN_MAX_FINDINGS` (200k held) and when a build would exceed `LINCHPIN_MAX_EDGES` (1M, checked before the work); `k` <= 1000, `budget` <= 50, what-if lists <= 1000 (422) |
| Elevation of privilege | XML entity expansion in the parser | `defusedxml` (a hard dependency) rejects internal and external entity declarations |

## Misuse considerations

The tool could be pointed at stolen scan data to plan an attack. Its output (ranked choke points) is the same thing a defender needs, and it contains nothing that helps with exploitation: no exploit mapping, no payloads, no target interaction. That is the main reason the project is defensively scoped.

## Model-correctness risks

The cost model is heuristic. `prerequisite_match` is fixed, credential reuse ignores network reachability, and reachability is modelled per segment. Every recommendation lists its evidence path ids so an analyst can verify it. Treat the output as decision support, not ground truth.

## v0.2 additions

| Asset / entry point | Threat | Mitigation |
| --- | --- | --- |
| XML exports (OpenVAS, Nessus, nmap) | XXE, billion laughs | `defusedxml` by default; entity declarations refused without it |
| Dataset downloader | tampered sample files | commit-pinned URLs plus SHA-256 verification; HTTPS only; reports only, never binaries |
| Web UI (`/ui`) | CDN compromise, XSS from finding strings | Cytoscape pinned with SRI; all finding text HTML-escaped before insertion; Swagger UI / ReDoc (unpinned CDN scripts) are off unless `LINCHPIN_API_DOCS=1` |
| `/demo/load` scenario path | reading arbitrary server files, NTLM leaks via UNC paths | only a *relative name* under `LINCHPIN_SCENARIO_DIR` (or the configured `LINCHPIN_SCENARIO`); absolute, drive, UNC, device and `..` paths are refused by their text before any filesystem call; every file the scenario lists must stay inside `LINCHPIN_DATA_DIR` (403). v1.0.0 accepted any server path here: upgrade |
| Neo4j mirror | credential leakage; cross-origin access to Neo4j's HTTP API | password only via `NEO4J_PASSWORD` (compose refuses to start without it), never in config; ports bound to localhost; compose restricts Neo4j's CORS origin to its own Browser |
| Findings with a malformed `detail` | crash the graph build (500 until restart) | per-kind `detail` validation at ingest (`models.detail_problem`); invalid records are rejected or dropped and logged, and the builder skips them |
| Cypher export | scanned banners containing `$graph` break the script | single-pass parameter substitution in `to_cypher`, escaped map keys |
