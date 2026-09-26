# Benchmarks & results

All numbers are produced by scripts in `benchmarks/` and written to `benchmarks/results/`. This page includes
those files verbatim. Everything is seeded. EPSS and KEV are rolling feeds, so exact numbers shift slightly with
the download date (recorded in each output).

## Real-export case study

Real findings and intel (OpenVAS scan of Metasploitable 2, a Greenbone Windows Server 2019 report, a Nessus scan of
`testphp.vulnweb.com`, two nmap exports, the SharpHound `TESTLAB.LOCAL` collection including its ACEs), placed into a
**declared** topology (`scenarios/composite_lab.yaml`). Crown jewel: the NTDS on the domain controller.

--8<-- "benchmarks/results/case_study.md"

## Synthetic topologies: 4 families x 50 seeds, real CVE parameters

Each planted vuln is drawn from a seeded sample of 3,000 real CVEs (300 in KEV) with its NVD vector, exploitability
sub-score, EPSS and KEV status. Graphs have 12-60 hosts; budget = 3 fixes.

![strategies](img/results/strategies.png)

--8<-- "benchmarks/results/summary.md"

## M11 learned exploitability (temporal split)

--8<-- "benchmarks/results/ml_exploitability.md"

## Performance

![scale](img/results/scale.png)

On a laptop (i5-13500H), build + rank (k=10) + optimise (budget 5, k=100) takes about 0.7 s at 467 nodes
(`single`) and 2 s at 373 nodes (`ad`). Roughly 900 nodes / 38k edges take 5-6 s. Raw timings are in
`benchmarks/results/scale.json`.
