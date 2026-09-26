PY ?= python
DATA ?= ../../datasets/linchpin
export PYTHONPATH := src
LP = $(PY) -m linchpin --state .linchpin/findings.json

.PHONY: install test lint data intel bench bench-quick casestudy ml scale demo demo-real api clean

install:
	$(PY) -m pip install -e ".[dev,api,ml,bench]"

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check .

## real data: public feeds + sample exports (~290 MB, outside the repo), then the intel cache
data:
	$(PY) scripts/download_data.py --out $(DATA)
	$(LP) intel-build --data-dir $(DATA)

## benchmarks (results land in benchmarks/results/)
bench:
	$(PY) benchmarks/run_benchmark.py --seeds 50 --budget 3
bench-quick:
	$(PY) benchmarks/run_benchmark.py --seeds 5 --budget 3 --out benchmarks/results/quick
casestudy:
	$(PY) benchmarks/case_study.py --data-dir $(DATA)
ml:
	$(PY) benchmarks/ml_exploitability.py --intel $(DATA)/derived/cve_intel.csv.gz
scale:
	$(PY) benchmarks/scale.py

demo:
	$(LP) synth --hosts 20 --seed 0 --out data/synth.json
	$(LP) ingest --replace data/synth.json
	$(LP) build
	$(LP) paths --k 3 --explain
	$(LP) fix --budget 3
	$(LP) cuts
	$(LP) whatif --remove jump-01

demo-real:
	$(LP) scenario scenarios/composite_lab.yaml --data-dir $(DATA)
	$(LP) paths --k 3 --explain
	$(LP) fix --budget 3
	$(LP) cuts

api:
	LINCHPIN_SCENARIO=$(SCENARIO) LINCHPIN_DATA_DIR=$(DATA) $(PY) -m uvicorn linchpin.api.app:app --host 127.0.0.1 --port 8000

clean:
	rm -rf .linchpin data .pytest_cache
