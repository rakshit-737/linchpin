PY ?= python
export PYTHONPATH := src
LP = $(PY) -m linchpin --state .linchpin/findings.json

.PHONY: install test demo bench api clean

install:
	$(PY) -m pip install -e ".[dev]"

test:
	$(PY) -m pytest -q

demo:
	$(LP) synth --hosts 20 --seed 0 --out data/synth.json
	$(LP) ingest --replace data/synth.json
	$(LP) build
	$(LP) paths --k 3 --explain
	$(LP) fix --budget 3
	$(LP) whatif --remove jump-01

bench:
	$(PY) benchmarks/ranking_vs_cvss.py 100 2

api:
	$(PY) -m uvicorn linchpin.api.app:app --host 127.0.0.1 --port 8000

clean:
	rm -rf .linchpin data .pytest_cache
