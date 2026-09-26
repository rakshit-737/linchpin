# Contributing

Thanks for helping. LINCHPIN is a defensive, read-only tool, and contributions must keep it that way.

## Ground rules

- **No exploit code, payloads, scanners or network clients.** Connectors parse files that already exist. PRs that add live target interaction will be declined.
- **Contracts are frozen** (`contracts/`). Changes must be additive and backwards compatible, and must be recorded in the contract file and in `CHANGELOG.md`.
- **No datasets in git.** Add a fetcher to `scripts/download_data.py` (pinned URL + SHA-256) and commit only tiny trimmed fixtures with provenance in `tests/fixtures/README.md`.
- Keep the engines deterministic: same input, same output, no LLMs in the decision path.

## Dev setup

```bash
pip install -e ".[dev,api,ml,bench]"
python -m ruff check .
python -m pytest -q                 # add -m realdata after scripts/download_data.py
```

## Adding a connector

1. `src/linchpin/connectors/<tool>.py` exposing `parse(path) -> list[NormalizedFinding]`.
2. Register it in `connectors/__init__.py` (`CONNECTORS` and `detect`).
3. Add a trimmed real export under `tests/fixtures/` and a golden test asserting the exact findings, schema validity and `finding_id` stability.

## Commits

Conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `data:`, `perf:`, `ci:`, `refactor:`), in small logical steps.
