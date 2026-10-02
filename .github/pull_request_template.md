## What and why

<!-- One or two sentences. Link the issue if there is one. -->

## Checklist

- [ ] `python -m ruff check .` and `python -m pytest -q` pass locally
- [ ] Stays read-only: no scanning, exploitation, payloads or target interaction (CONTRIBUTING.md)
- [ ] Contract changes (`contracts/`) are additive and recorded in the contract file and `CHANGELOG.md`
- [ ] No datasets, real scan exports or files over 1 MB committed; new fixtures are trimmed and listed in `tests/fixtures/README.md`
- [ ] If results change: benchmark re-run, numbers in README/docs updated from the committed result files
