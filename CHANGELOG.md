# Changelog

## [Unreleased]

## [1.1.2] - 2026-10-03

### Fixed
- SECURITY.md's supported-versions row still pointed at the v1.1.0 release and image tag; it now names the latest
  1.1.x release and the current image tag.

## [1.1.1] - 2026-10-03

### Fixed
- `ingest`: a truncated XML report or malformed topology YAML/JSON is reported under `skipped` with its line and
  column instead of aborting the batch with a traceback; `--replace` drops the old `config.json` only after the inputs
  parsed, and when no input can be read the state is left alone and the command exits 1.
- `whatif` (CLI exit 2, `POST /whatif` 422) rejects node ids that are not in the graph instead of reporting that
  removing them changes nothing.
- The API sets `X-Frame-Options: DENY`, `Content-Security-Policy: frame-ancestors 'none'`, `X-Content-Type-Options:
  nosniff` and `Referrer-Policy: no-referrer` on every response.
- The committed preprint PDF predated the v1.1.0 source edit and still said the prospective intervals "overlap".

### Added
- Paired statistics: the EPSS-vs-CVSS comparison is paired on the same exploited CVEs (prospective label: 20 vs 5
  discordant, exact McNemar p = 0.0041, +24.2 points [9.7, 38.7]); Wilson intervals replace the 200-replicate
  bootstrap for reproduction proportions; the effort ratio gets a 1,000-replicate bootstrap (0.701 [0.695, 0.824],
  which excludes the paper's 0.671); paired cost-gain tests in the benchmark and ablation; a paired AUC / AP bootstrap
  for M11 (`benchmarks/ml_paired.py`).
- Benchmark: the best patch-only plan (LINCHPIN restricted to vulnerabilities, 95% [90, 97]) as the like-for-like
  ceiling for score queues; every strategy tested against random; residual difference per family.
- Ablation: identity result over the families where it can matter (`ad` + `multi`: 100/100 vs 5/100); the fused and
  uniform-cost plans are also scored with uniform costs. Real-export case study: the same identity ablation on real
  data.
- Provenance: every result JSON records the commit (and a dirty flag) or the CI run that produced it; the lab and GDS
  artefacts record their run id and the pulled image digests; a manual `results` workflow regenerates the benchmark
  and ablation (run 37089520295 reproduced every outcome cell of the v1.1.0 tables).
- CI: the paper job fails when the committed PDF's text differs from a fresh build; the docs job parses every mermaid
  block; the GDS cross-check times 10 runs per backend (median and IQR); release builds attest provenance for the
  image, wheel and sdist.
- `benchmarks/results/repro_epss_paper_check.md`: every transcribed Jacobs et al. cell checked against the arXiv v2
  PDF (all match); a test pins them.
- Sub-command `--help` pages have descriptions and examples.

### Changed
- Results that got worse or narrower: scored with uniform edge costs, the uniform-cost plan beats the fused plan on
  `none` (-0.054 [-0.082, -0.027]), so the ablation no longer supports "exploit intel improves the cost gain"; the
  identity result is stated per family (it is designed into the generator) instead of as a pooled "decisive" effect;
  the reproduction is called a partial replication (117,141 of the paper's ~191k CVEs), and its effort ratio interval
  excludes the paper's value; GDS speed-ups are reported as 1.4-39x across four CI runs instead of 4-31x from one.
- Untraceable timing claims (session variation, optimiser A/B re-timing, the 37 s / 70 s install times) were removed;
  the quick start installs the v1.1.0 tag instead of `main`.
- Paper: retitled "An Open Evaluation of LINCHPIN with a Measured Lab"; cites TVA, NetSPA and CyGraph; random and
  patch-only rows in Table 1; the ablation table fits the page.

## [1.1.0] - 2026-10-02: measured lab, ablation, published baselines, reproduction, preprint

### Security
- **API (v1.0.0 is affected, see SECURITY.md):** `/demo/load` read any server-side path as a scenario; `k`, `budget` and
  request bodies were unbounded; the `Host` header was not checked. Now: Host allow-list (`LINCHPIN_ALLOWED_HOSTS`,
  DNS-rebinding guard), 413 above `LINCHPIN_MAX_BODY_MB` / `LINCHPIN_MAX_FINDINGS` / `LINCHPIN_MAX_EDGES` (checked
  before the quadratic build pass), bounded query parameters, scenarios only by relative name under configured
  directories with every listed file confined (paths refused by their text before any filesystem call), per-kind
  `detail` validation, Swagger UI / ReDoc only with `LINCHPIN_API_DOCS=1`.
- `to_cypher` substitutes parameters in one pass (a banner containing `$graph` broke the exported script); Neo4j
  `connect()` verifies connectivity; compose no longer ships a fixed Neo4j password and limits Neo4j's CORS origin.
- Supply chain: actions pinned to commit SHAs, Docker base image by digest, hash-pinned `requirements.lock`, dependency
  floors raised past published advisories (starlette >= 1.3.1, scikit-learn >= 1.5), pip-audit of the lock and of the
  lowest allowed versions; secret scanning, push protection, Dependabot alerts / updates, CodeQL and private
  vulnerability reporting enabled; `main` rejects force-pushes and deletion.

### Added
- **Measured case study:** the `lab-scan` CI job scans old official images on internal Docker networks with
  `nmap -sV` (no scripts), derives the topology from the measurement, maps versions to CVEs offline and checks the
  plan (`lab/`, `benchmarks/lab_case_study.py`, `scenarios/lab_scan.yaml`, `benchmarks/results/lab/`).
- **Offline version-to-CVE matching:** `linchpin.intel.cpe` with a packaged NVD version-range index
  (`scripts/build_cpe_index.py`, 113 kB); `ingest --match-cpe`, scenario `match_cpe: true`; "upgrade X" fixes.
- **Published baselines:** exact budgeted shortest-path interdiction MILP (Israeli & Wood 2002, HiGHS) and a Guo et
  al.-style greedy interdiction (`linchpin.engine.interdiction`); CVSS / EPSS / KEV queues restricted to on-path vulns.
- **Ablation** (`benchmarks/ablation.py`): degraded data views, identity dose-response, uniform edge costs, exact
  McNemar tests, bootstrap intervals.
- **Reproduction** of Jacobs et al. (IEEE EuroS&PW 2023) with the archived EPSS scores of 2022-12-01, as-of and
  prospective KEV labels, bootstrap intervals and provenance.
- **Neo4j GDS backend** (`gds_k_shortest_paths`) with a strict CI cross-check sweep.
- **Contract v1.3:** credential use scored by network reachability (`prerequisite_match`), additive.
- CLI: `--version`, help everywhere, `serve`, `synth --family`, friendly errors; `ingest` applies topology `match:`
  aliases and explains empty results. Generated CLI reference; docstrings on the whole public API (ruff-enforced).
- UI: crown-jewel filter, what-if before/after bars; static demo with budgets 1-10 and an honest seed control.
- Docs: How it works, Evaluation (methodology, all results, threats to validity), Reproduce; ADR 0005; references.
- Preprint in `paper/` (built in CI); CITATION.cff, issue / PR templates, CODEOWNERS, Dependabot.
- CI: Python 3.10-3.14, wheel and sdist checks, Docker smoke test, docs checks on pull requests, weekly schedule,
  release gated on the full CI and on a smoke-tested image.

### Fixed
- The v1.0.0 wheel and image did not contain the CVE pool and silently planted placeholder `CVE-2099-*` vulns; the
  pool is package data now and a missing pool is an error.
- The live `/demo/` page served the MkDocs "Live demo" page instead of the explorer.
- `linchpin ingest exports... topology.yaml` ignored the topology's host aliases and returned an empty plan with exit 0.
- `/paths?from=` (frozen contract) was ignored; only `frm` worked.
- Path ties depended on `PYTHONHASHSEED`; the case-study JSON changed between runs.
- `ablation.py --families none` crashed; the GDS CI job could pass without reaching Neo4j or running GDS.
- The legacy synthetic generator's placeholder ids looked like real CVEs (now `CVE-2099-*`).

### Results changed (including worse numbers)
- **M11** learned exploitability: the v1.0 numbers (ROC-AUC 0.863, average precision 0.063, "about 5x CVSS") came from
  training on today's KEV labels and descriptions that state exploitation. With labels known at the cutoff and those
  sentences masked: ROC-AUC 0.836, average precision 0.028 vs 0.011 for CVSS (about 2.4x). The "brand-new CVEs" claim
  was dropped.
- **EPSS reproduction:** the v1 table misquoted the paper and compared a different population; corrected (see
  `repro_epss.md`). The all-CVE effort ratio is 0.29, not "about one third, like the paper's one-eighth".
- **Benchmark:** sizes now 12-60 hosts (the old formula produced 7 sizes up to 54); several baseline rates moved (ad
  CVSS-first 14% -> 8%, single betweenness 88% -> 84%); the decoys and noise vulns are disclosed.
- **Case study:** "135 findings from 6 exports" was 119 exported + 16 overlay; one of the three ACE nodes is reachable
  from the entry points (none lies on a path to the crown jewel).
- **Performance:** re-measured as medians on an idle laptop: 1.1 s at 467 nodes (v1.0 reported 0.7 s from a single
  run). (A session-to-session variation figure and A/B timings quoted here at release had no committed raw data and
  were removed in the next release.)
- The 0.2.0 "about 4x faster optimiser" claim was withdrawn; the re-timing quoted here at release had no committed raw
  data.

## 1.0.0 (2026-09-26): ACL paths, weighted cuts, docs site, releases

### Added
- **BloodHound ACE edges** (contracts v1.2, additive): `Ace` nodes with `HAS_ACE` / `ABUSES` edges for GenericAll/GenericWrite, WriteDacl/WriteOwner/Owns, ForceChangePassword, AddMember/AddSelf, AllExtendedRights, AddAllowedToAct (RBCD), ReadLAPSPassword and DCSync (GetChanges + GetChangesAll). "Remove ACE" is a remediation type.
- **Effort-weighted minimum cut** (`cuts --weighted`, `/chokepoints?weighted=true`, config `fix_cost`).
- **Confidence intervals:** 95% Wilson intervals for disconnect rates, seeded bootstrap intervals for attacker-cost gain, and class-stratified bootstrap intervals for the ML ROC-AUC / average precision.
- **Static demo** of the path explorer on GitHub Pages (`scripts/build_static_demo.py`, in-browser what-if).
- **Playwright browser smoke tests** (live API and static demo) and a CI `ui` job.
- **MkDocs Material docs site** with mkdocstrings API reference, deployed by `docs.yml`.
- **Dockerfile** (slim, non-root), compose now builds it; `release.yml` pushes `ghcr.io/rakshit-737/linchpin` and creates a GitHub Release with wheel and sdist.

### Fixed
- Configured (non-internet) entry hosts could be proposed as a "segmentation" fix and appear in min cuts.
- `benchmarks/results/summary.md` was written in the Windows code page instead of UTF-8.
- Threat model still listed defusedxml as TODO; package `__version__` was stale.

### Results changed
- Case study: 135 findings, 128 nodes / 224 edges (3 ACE nodes, none reachable from the declared entry points); the plan is unchanged.

## 0.2.0 (2026-09-26): real data

### Added
- **Connectors:** OpenVAS/Greenbone XML, Nessus `.nessus`, nmap `vulners` CVEs, SharpHound/BloodHound v5/v6 JSON (admin rights with nested groups, sessions, DA/DC), topology/inventory overlay YAML. Format auto-detection and `defusedxml`.
- **Exploit intel:** NVD CVE 2.0, FIRST EPSS and CISA KEV parsers; a 379k-CVE lookup cache (`linchpin intel-build`); finding enrichment.
- **Scenario loader:** real exports, declared topology, host aliasing and intel in one YAML (`scenarios/composite_lab.yaml`).
- **Engine:** exact minimum remediation cut (vertex max-flow) and chokepoints (dominators); the optimizer uses the exact cut when it fits the budget.
- **M11:** learned exploit-likelihood model (KEV label, temporal split). Opt in with `exploitability_source: learned`.
- **Neo4j adapter:** push/pull mirror using the frozen taxonomy, `.cypher` export, and a live CI job.
- **Web UI:** Cytoscape.js path explorer, evidence highlighting and what-if, served at `/ui`.
- **Benchmarks:** four topology families (single / multi / none / AD) using a real CVE pool, six baselines, the real-export case study and a scaling run.
- **CLI:** `scenario`, `intel-build`, `cuts`, `export`, `neo4j-push`; `ingest --intel`.
- Checksummed dataset downloader; LICENSE, CONTRIBUTING, ADRs.

### Changed (additive to the frozen contracts)
- Edge cost prefers the NVD CVSS *exploitability sub-score* and floors exploitability at 0.95 for KEV entries.
- A vuln grants a privilege only if its CVSS vector (or a conservative heuristic) implies code execution.
- Faster optimiser (first reported as "about 4x"; that figure is withdrawn, no raw timings were kept): Yen runs on the entry-to-crown subgraph, and reachability no longer copies the graph.

## 0.1.0

- MVP: frozen contracts, in-memory GraphStore, edge cost, Yen paths, greedy optimizer, templated explanations, FastAPI, CLI, synthetic generator and benchmark.
