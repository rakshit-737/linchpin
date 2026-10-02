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
- All XML parsers go through `defusedxml` (a hard runtime dependency), which refuses internal and external entity declarations.
- The API has no authentication and binds to `127.0.0.1` (`linchpin serve`, Makefile, compose). It only answers requests whose `Host` header is on `LINCHPIN_ALLOWED_HOSTS`, bounds body size, stored findings and graph size, and reads server-side scenarios only by relative name inside configured directories (see the [API reference](https://rakshit-737.github.io/linchpin/reference/api/)). Do not expose it to a network.
- Findings describe weaknesses. Treat ingested data and `.linchpin/` state files as sensitive and keep them out of version control (they are already in `.gitignore`).

## Known issues in released versions

- **v1.0.0** (wheel, sdist and `ghcr.io/rakshit-737/linchpin:1.0.0`): `/demo/load` accepted any server-side file path
  as a scenario, `k` / `budget` were unbounded and request bodies unlimited, and the `Host` header was not checked.
  Anyone who can reach the API (or a DNS-rebinding page in a local browser) could read files the server can parse
  or exhaust CPU. Fixed on `main`; run v1.0.0 only bound to localhost with no browser on the same host, or upgrade
  to the next release.

## Reporting a vulnerability

Please open a private security advisory on the repository, or email the maintainer, instead of filing a public issue. Include reproduction steps. The maintainer aims to reply within 7 days.

## Supply chain

CI runs `bandit` (SAST) and `pip-audit` (dependency CVEs) on every push. Runtime dependencies are limited to pydantic, networkx, PyYAML and defusedxml; FastAPI/uvicorn, neo4j, scikit-learn and matplotlib are optional extras. The web UI loads Cytoscape.js from jsDelivr pinned by version with a Subresource-Integrity hash.
