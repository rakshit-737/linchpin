# HTTP API

`uvicorn linchpin.api.app:app --host 127.0.0.1 --port 8000`. Interactive OpenAPI docs are served at `/docs`.
The frozen contract is [`contracts/openapi.yaml`](https://github.com/rakshit-737/linchpin/blob/main/contracts/openapi.yaml).
Bind to localhost only: there is no authentication.

| method | path | returns |
| --- | --- | --- |
| POST | `/ingest` | accepted / rejected counts for a list of `NormalizedFinding` |
| POST | `/graph/build` | node / edge counts, build time |
| GET | `/paths?k=10&to=crown_jewels&frm=` | ranked `AttackPath` list |
| GET | `/remediations?budget=5&k=100` | ordered `Remediation` list with rationale and evidence |
| GET | `/nodes/{id}` | node detail |
| POST | `/whatif` | `PathStats` after removing `remove_nodes` |
| GET | `/graph` | Cytoscape elements |
| GET | `/chokepoints?weighted=false` | chokepoints, exact min cut (and the minimum-effort cut) |
| GET | `/criticality` | nodes by share of top paths |
| GET | `/stats` | counts, entrypoints, crown jewels |
| POST | `/demo/load` | load a synthetic family or the server-side scenario |
| GET | `/ui` | the path explorer |
