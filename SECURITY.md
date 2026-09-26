# Security Policy

## Scope and intended use

LINCHPIN is a **read-only analysis tool**. It:

- contains no exploit code, no payloads, and no scanning or network-client code;
- only parses files that already exist (nmap XML exports and JSON findings) or generates synthetic data;
- never contacts the hosts described in its input.

Only feed it data from environments you own or are explicitly authorised to assess, such as an isolated host-only lab or the built-in synthetic generator. If a live-ingest connector is ever added, it must be off by default and gated behind an explicit opt-in flag.

## Handling input

- Finding files are untrusted input. Every record is validated against the pydantic `NormalizedFinding` contract, and invalid records are dropped.
- The nmap parser uses the stdlib `xml.etree`. For untrusted XML from outside your own lab, install and switch to `defusedxml` (TODO: make that the default).
- The API has no authentication and binds to `127.0.0.1` in the Makefile and docker-compose. Do not expose it to a network.
- Findings describe weaknesses. Treat ingested data and `.linchpin/` state files as sensitive and keep them out of version control (they are already in `.gitignore`).

## Reporting a vulnerability

Please open a private security advisory on the repository, or email the maintainer, instead of filing a public issue. Include reproduction steps. The maintainer aims to reply within 7 days.

## Supply chain

CI runs `bandit` (SAST) and `pip-audit` (dependency CVEs) on every push. Runtime dependencies are limited to pydantic, networkx and PyYAML; FastAPI and uvicorn are optional.
