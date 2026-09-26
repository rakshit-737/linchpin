# Security Policy

## Scope and intended use

LINCHPIN is a **read-only analysis tool**. It:

- contains no exploit code, no payloads, and no scanning or network-client code;
- only parses files that already exist (nmap / OpenVAS / Nessus XML, SharpHound JSON, inventory YAML, JSON findings) or generates synthetic data;
- the dataset downloader (`scripts/download_data.py`) fetches public feeds and sample *reports* only (NVD, EPSS, KEV, DefectDojo test scans, BloodHound test fixtures) from fixed HTTPS URLs, pinned by commit and SHA-256 where possible; no binaries, no malware, no exploit code;
- never contacts the hosts described in its input.

Only feed it data from environments you own or are explicitly authorised to assess, such as an isolated host-only lab or the built-in synthetic generator. If a live-ingest connector is ever added, it must be off by default and gated behind an explicit opt-in flag.

## Handling input

- Finding files are untrusted input. Every record is validated against the pydantic `NormalizedFinding` contract, and invalid records are dropped.
- All XML parsers go through `defusedxml` (a runtime dependency); if it is missing, documents containing entity declarations are refused.
- The API has no authentication and binds to `127.0.0.1` in the Makefile and docker-compose. Do not expose it to a network.
- Findings describe weaknesses. Treat ingested data and `.linchpin/` state files as sensitive and keep them out of version control (they are already in `.gitignore`).

## Reporting a vulnerability

Please open a private security advisory on the repository, or email the maintainer, instead of filing a public issue. Include reproduction steps. The maintainer aims to reply within 7 days.

## Supply chain

CI runs `bandit` (SAST) and `pip-audit` (dependency CVEs) on every push. Runtime dependencies are limited to pydantic, networkx, PyYAML and defusedxml; FastAPI/uvicorn, neo4j, scikit-learn and matplotlib are optional extras. The web UI loads Cytoscape.js from jsDelivr pinned by version with a Subresource-Integrity hash.
