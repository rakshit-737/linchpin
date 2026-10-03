# Reproduce

Every result in [Evaluation](evaluation.md) comes from one of the commands below. Runtimes were measured on the
author's laptop (Intel i5-13500H, 16 GB RAM, Windows 11, Python 3.14); CI runs the fast ones on every push.
Everything is seeded and deterministic: re-running a step rewrites its result files byte for byte (only the timing
columns of `rows.csv`, `scale.json` and the `runtime_s` fields change).

## 0. Setup

```bash
git clone https://github.com/rakshit-737/linchpin && cd linchpin
pip install -e ".[dev,api,ml,bench,docs]"
python -m pytest -q          # real-data, live-Neo4j and browser tests skip without the datasets / server / Chromium
```

## 1. Data (outside the repo)

| command | time | output |
| --- | --- | --- |
| `python scripts/download_data.py` | a few minutes (about 270 MB) | `../../datasets/linchpin/`: NVD feeds, EPSS (current and 2022-12-01), KEV, sample exports, `MANIFEST.sha256` |
| `linchpin intel-build --data-dir ../../datasets/linchpin` | about 5 min | `derived/cve_intel.csv.gz` (379,082 CVEs) |
| `python scripts/build_cve_pool.py` | under 1 min | `src/linchpin/synth/data/cve_pool.csv` (3,000 CVEs, seed 7; committed) |
| `python scripts/build_cpe_index.py --data-dir ../../datasets/linchpin` | 94 s | `src/linchpin/intel/data/cpe_index.csv.gz` (27,095 version ranges; committed) |

The benchmark and ablation need only the committed CVE pool, not the downloads.

## 2. Results

| command | time | writes | expect |
| --- | --- | --- | --- |
| `python benchmarks/run_benchmark.py --seeds 50 --budget 3 --workers 8` | 11.5 min on the laptop (8 workers); 3.7 min in CI (4 workers) | `summary.{json,md}`, `rows.csv`, `strategies.png` | pooled disconnect 100% LINCHPIN and MILP, 97% greedy interdiction, 95% best patch-only plan, 39% betweenness, 3-10% score queues and random; `none`: 0.83 of the optimal cost gain |
| `python benchmarks/ablation.py --seeds 50 --budget 3 --workers 8` | 14 min on the laptop (8 workers); 9 min in CI (4 workers) | `ablation.{json,md}`, `ablation_rows.csv` | `ad` + `multi`: fused 100/100, no identity 5/100; pooled: fused 100%, no identity 37%, identity only 18%, KEV->EPSS 3% |
| `python benchmarks/repro_epss.py --data-dir ../../datasets/linchpin` | about 5 min (paired and ratio bootstraps) | `repro_epss.{json,md}` | paper-like: CVSS 7+ effort 58.2% (paper 58.1%); effort ratio 0.701 [0.695, 0.824]; prospective: 20 vs 5 discordant, McNemar p = 0.0041 |
| `python benchmarks/ml_exploitability.py` | 45-70 min (three trainings with 200-replicate bootstraps) | `ml_exploitability.{json,md}`, `derived/exploit_model.npz` | test CVEs without exploitation-status phrases: ROC-AUC 0.836, AP 0.028 vs 0.011 for CVSS |
| `python benchmarks/ml_paired.py --data-dir ../../datasets/linchpin` | about 25 min on a busy laptop (1,000 paired replicates; no training) | `ml_paired.{json,md}` | AUC difference +0.082 [0.065, 0.100]; AP ratio 2.43x [1.90, 3.24] |
| `python benchmarks/case_study.py --data-dir ../../datasets/linchpin` | about 1 min | `case_study.{json,md}` | 128 nodes, 224 edges; first fix: rotate `ADMINISTRATOR@TESTLAB.LOCAL`; without identity findings: no path seen, no fix |
| `python benchmarks/lab_case_study.py --scans benchmarks/results/lab` | 4 s | `lab/lab_case_study.{json,md}`, `lab/topology.yaml` | 5 of 6 services matched, 393 CVEs (7 KEV); 1 fix (upgrade Tomcat 9.0.30) |
| `python benchmarks/scale.py --reps 5` | about 4 min | `scale.{json,png}` | about 1.1 s at 467 nodes on the laptop (one session's medians) |
| `python scripts/make_figures.py` | 10 s | `docs/img/how/*.png`, copies the result figures into `docs/img/results/` | |
| `python scripts/build_static_demo.py --data-dir ../../datasets/linchpin` | 39 s | `docs/demo/` | five snapshots, budgets 1-10 |
| `python scripts/gen_cli_reference.py` | 1 s | `docs/reference/cli.md` | (a test fails when it is stale) |

`make bench`, `make casestudy`, `make ml`, `make scale` and `make demo` wrap the same commands. The `results`
workflow (Actions tab, run manually) runs the benchmark and the ablation on a clean Linux runner and uploads their
result files; the committed tables come from its run
[37089520295](https://github.com/rakshit-737/linchpin/actions/runs/37089520295). Every result JSON records the commit
(and whether code had uncommitted changes) or the CI run that produced it.

## 3. Live environments (GitHub Actions only)

These need Docker and run on ephemeral `ubuntu-24.04` runners; locally, the committed artefacts can be replayed.

| CI job | what it does | committed artefact |
| --- | --- | --- |
| `lab-scan` | `lab/up.sh` starts httpd 2.4.49, nginx 1.16.1, tomcat 9.0.30, redis 5.0.7 and mysql 5.5.62 on two `--internal` networks; `lab/scan.sh` runs `nmap -sV` (no scripts) from a container inside each; `benchmarks/lab_case_study.py` plans and checks | `benchmarks/results/lab/` (run [37091866743](https://github.com/rakshit-737/linchpin/actions/runs/37091866743), recorded in `lab_case_study.json`) |
| `neo4j-gds` | Neo4j 5.26 Community with GDS 2.13.13; Yen in GDS vs NetworkX on 250 and 500 hosts, k = 10 and 100 | `benchmarks/results/gds_crosscheck.json` (run [37091866743](https://github.com/rakshit-737/linchpin/actions/runs/37091866743), recorded in the file) |
| `neo4j` | live push / pull round trip | |
| `ui` | Playwright against the live API and the built static demo | |
| `paper` | builds `paper/linchpin.pdf` from LaTeX and fails if the committed PDF's text differs from the fresh build | the PDF |

## 4. Docs

```bash
mkdocs build --strict && grep -q LINCHPIN_STATIC site/demo/index.html   # what CI's docs job checks
npm install --no-save mermaid@11.17.2 jsdom@26.1.0 && node scripts/check_mermaid.mjs   # every mermaid block parses
```
