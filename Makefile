PY ?= python
DATA ?= ../../datasets/linchpin
export PYTHONPATH := src
LP = $(PY) -m linchpin --state .linchpin/findings.json

.PHONY: install test lint data intel bench bench-quick ablation repro casestudy labcase ml scale figures demo demo-real api paper clean

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
WORKERS ?= 8
bench:
	$(PY) benchmarks/run_benchmark.py --seeds 50 --budget 3 --workers $(WORKERS)
ablation:
	$(PY) benchmarks/ablation.py --seeds 50 --budget 3 --workers $(WORKERS)
repro:
	$(PY) benchmarks/repro_epss.py --data-dir $(DATA)
labcase:
	$(PY) benchmarks/lab_case_study.py --scans benchmarks/results/lab
figures:
	$(PY) scripts/make_figures.py
bench-quick:
	$(PY) benchmarks/run_benchmark.py --seeds 5 --budget 3 --out benchmarks/results/quick
casestudy:
	$(PY) benchmarks/case_study.py --data-dir $(DATA)
ml:
	$(PY) benchmarks/ml_exploitability.py --intel $(DATA)/derived/cve_intel.csv.gz
scale:
	$(PY) benchmarks/scale.py --reps 5

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
	$(LP) serve $(if $(SCENARIO),--scenario $(SCENARIO) --data-dir $(DATA),)

paper:
	cd paper && latexmk -pdf linchpin.tex

clean:
	rm -rf .linchpin data .pytest_cache
