# Getting started

## Install

```bash
git clone https://github.com/rakshit-737/linchpin && cd linchpin
pip install -e ".[dev,api,ml,bench]"
python -m pytest -q        # real-data and live-Neo4j tests auto-skip without data / server
```

Or with Docker (API + UI on localhost only):

```bash
docker compose up api                    # http://127.0.0.1:8000/ui
docker run --rm -p 127.0.0.1:8000:8000 ghcr.io/rakshit-737/linchpin:latest
```

## Synthetic demo (no downloads)

```bash
export PYTHONPATH=src
python -m linchpin synth --hosts 20 --seed 0 --out data/synth.json
python -m linchpin ingest --replace data/synth.json
python -m linchpin fix --budget 3
python -m linchpin cuts --weighted
python -m linchpin whatif --remove jump-01
```

## Your own lab exports

```bash
python -m linchpin ingest --replace openvas.xml scan.nessus nmap.xml sharphound_dir/ topology.yaml \
       --intel ../../datasets/linchpin/derived/cve_intel.csv.gz
python -m linchpin paths --k 5 --explain
python -m linchpin fix --budget 5
```

The topology overlay YAML declares segments, internet-facing hosts, reachability rules and crown jewels; see
[`scenarios/composite_lab.yaml`](https://github.com/rakshit-737/linchpin/blob/main/scenarios/composite_lab.yaml).

## Web UI

```bash
uvicorn linchpin.api.app:app --host 127.0.0.1 --port 8000   # open http://127.0.0.1:8000/ui
```

## Reproduce the results

```bash
python scripts/download_data.py                                    # ~270 MB, checksummed
python -m linchpin intel-build --data-dir ../../datasets/linchpin  # ~5 min
python benchmarks/run_benchmark.py --seeds 50 --budget 3           # ~25 min
python benchmarks/case_study.py
python benchmarks/ml_exploitability.py                             # ~5 min with 200 bootstrap replicates
python benchmarks/scale.py
python scripts/build_static_demo.py                                # regenerates docs/demo/
```

`make` is optional; the Makefile targets wrap the same commands.
