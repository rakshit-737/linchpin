# Getting started

## Install

```bash
git clone https://github.com/rakshit-737/linchpin && cd linchpin
pip install -e .                       # core: CLI, engines, connectors (pydantic, networkx, PyYAML, defusedxml)
pip install -e ".[api]"                # + FastAPI service and web UI (`linchpin serve`)
pip install -e ".[dev,api,ml,bench]"   # everything needed for the tests and benchmarks
python -m pytest -q                    # real-data, live-Neo4j and browser tests auto-skip without data / server / Chromium
```

The distribution is called `linchpin-attackpath` (the PyPI name `linchpin` belongs to an unrelated project); the
command and the import package are `linchpin`. Do not `pip install linchpin` from PyPI expecting this tool.

Or with Docker (API + UI, bound to localhost only):

```bash
docker build -t linchpin . && docker run --rm -p 127.0.0.1:8000:8000 linchpin   # http://127.0.0.1:8000/ui
docker compose up api                                                              # same, via compose
```

Release images are published to `ghcr.io/rakshit-737/linchpin`; v1.0.0 has known issues (see
[Security](security.md#known-issues-in-released-versions)), so use a later version.

## Synthetic demo (no downloads)

```bash
linchpin synth --hosts 20 --seed 0 --out data/synth.json   # family `single`, real CVE parameters
linchpin ingest --replace data/synth.json
linchpin fix --budget 3
linchpin cuts --weighted
linchpin whatif --remove jump-01
linchpin synth --family ad --hosts 30 --out data/ad.json   # or multi / none / legacy
```

## Your own lab exports

Put the exports and a topology overlay in one scenario YAML (see
[`scenarios/composite_lab.yaml`](https://github.com/rakshit-737/linchpin/blob/main/scenarios/composite_lab.yaml)
and the measured [`scenarios/lab_scan.yaml`](https://github.com/rakshit-737/linchpin/blob/main/scenarios/lab_scan.yaml)):
it declares segments, internet-facing hosts, firewall rules and crown jewels, and lists under each host's `match:` the
ids the scanners used for it, so findings from different tools merge onto one node.

```bash
linchpin intel-build --data-dir ../../datasets/linchpin             # NVD + EPSS + KEV cache, once
linchpin scenario my_lab.yaml --data-dir path/to/exports
linchpin paths --k 5 --explain
linchpin fix --budget 5
```

`linchpin ingest` accepts the same files directly, including the topology YAML:

```bash
linchpin ingest --replace openvas.xml scan.nessus nmap.xml sharphound_dir/ topology.yaml \
       --intel ../../datasets/linchpin/derived/cve_intel.csv.gz
linchpin ingest --replace --match-cpe nmap-sV.xml topology.yaml     # versions -> CVEs offline, no intel cache needed
```

It reports the graph's entry points, crown jewels and reachable crown jewels, and warns when a `match:` alias names no
host in the exports or nothing is reachable, so an empty plan never reads as "nothing to fix".

## Web UI

```bash
linchpin serve                                   # http://127.0.0.1:8000/ui (synthetic demo)
linchpin serve --scenario scenarios/composite_lab.yaml --data-dir ../../datasets/linchpin
```

The API answers only localhost `Host` headers by default (`LINCHPIN_ALLOWED_HOSTS`) and bounds request size, stored
findings and graph size; see the [HTTP API reference](reference/api.md#limits-and-environment).

## Reproduce the results

Every command, its runtime and the expected headline numbers: [Reproduce](reproduce.md).
