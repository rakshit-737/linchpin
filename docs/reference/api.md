# HTTP API

`linchpin serve` (or `uvicorn linchpin.api.app:app --host 127.0.0.1 --port 8000`). The OpenAPI schema is at
`/openapi.json`; the interactive Swagger UI (`/docs`) loads scripts from a CDN and is only served with
`LINCHPIN_API_DOCS=1`. The frozen contract is
[`contracts/openapi.yaml`](https://github.com/rakshit-737/linchpin/blob/main/contracts/openapi.yaml).
Bind to localhost only: there is no authentication.

| method | path | returns |
| --- | --- | --- |
| POST | `/ingest` | accepted / rejected counts for a list of `NormalizedFinding` |
| POST | `/graph/build` | node / edge counts, build time |
| GET | `/paths?k=10&to=crown_jewels&from=entrypoints` | ranked `AttackPath` list (`from` / `to` also take a node id or bare host name) |
| GET | `/remediations?budget=5&k=100` | ordered `Remediation` list with rationale and evidence |
| GET | `/nodes/{id}` | node detail |
| POST | `/whatif` | `PathStats` after removing `remove_nodes` |
| GET | `/graph` | Cytoscape elements |
| GET | `/chokepoints?weighted=false` | chokepoints, exact min cut (and the minimum-effort cut) |
| GET | `/criticality` | nodes by share of top paths |
| GET | `/stats` | counts, entrypoints, crown jewels |
| POST | `/demo/load` | load a synthetic family, or the server's scenario (`{"family": "scenario"}`) |
| GET | `/ui` | the path explorer |

## Limits and environment

| variable | default | effect |
| --- | --- | --- |
| `LINCHPIN_ALLOWED_HOSTS` | `127.0.0.1,localhost,::1` | other `Host` headers get 400 (DNS-rebinding guard); `*` disables the check |
| `LINCHPIN_MAX_BODY_MB` | `25` | larger request bodies get 413, also when streamed without `Content-Length` |
| `LINCHPIN_MAX_FINDINGS` | `200000` | `/ingest` answers 413 once the store would hold more findings |
| `LINCHPIN_MAX_EDGES` | `1000000` | a build whose projected edge count is larger answers 413 before doing the work |
| `LINCHPIN_SCENARIO` | unset | scenario YAML preloaded at start and used by `/demo/load {"family": "scenario"}` |
| `LINCHPIN_SCENARIO_DIR` | unset | `/demo/load` may name other scenarios here, as relative names only |
| `LINCHPIN_DATA_DIR` | unset | base directory for the exports a scenario lists; references may not leave it |
| `LINCHPIN_API_DOCS` | unset | `1` serves Swagger UI at `/docs` and ReDoc at `/redoc` |
| `LINCHPIN_DEMO` | `1` | `0` starts with an empty store instead of the synthetic `single` demo |

Query bounds: `k` 1..1000, `budget` 1..50, `top` 1..1000, at most 1000 ids per what-if and 200,000 findings
per `/ingest` call (422 / 413 beyond). Records that fail the schema or the per-kind `detail` check are counted
in `rejected` with their reasons, never stored.
