# Evaluation

Every number on this page is produced by a script in `benchmarks/` and written to `benchmarks/results/`; the result
tables below are those files, included verbatim. Everything is seeded and path enumeration does not depend on the
interpreter's hash seed. The rolling feeds are dated in each output (EPSS scores of 2026-09-25, KEV catalog
2026.09.25). Commands and runtimes: [Reproduce](reproduce.md).

## Methodology

**Topology families.** `linchpin.synth.topologies` generates four families, 50 seeds each, with 12 + (seed mod 49)
hosts (12-60 hosts, 58-317 attack-graph nodes):

* `single`: one bastion between the DMZ and everything else (exact min cut 1);
* `multi`: 2-3 parallel bastions and two independent routes into the database (min cut 2, no chokepoint);
* `none`: a flat network whose database exposes several code-execution services (min cut about 7, larger than the
  budget, so no 3-fix plan can disconnect it);
* `ad`: tiered Active Directory with helpdesk local-admin reuse and server-admin and Domain-Admin sessions cached on
  lower tiers (min cut 1.34 on average; half the seeds add a KEV-listed RCE on the domain controller).

Every family also contains **planted distractors**: two isolated hosts with a KEV-listed RCE of CVSS >= 9.0
(decoys nothing can reach) and high-CVSS vulnerabilities without code execution on reachable hosts (noise). They are
what a score-sorted queue spends its budget on, which is why the benchmark also runs the queues restricted to
vulnerabilities that lie on some entry-to-crown-jewel route.

**Vulnerability parameters** come from a KEV-enriched stratified sample of 3,000 real CVEs
(`src/linchpin/synth/data/cve_pool.csv`): NVD vector and exploitability sub-score, EPSS and KEV status. KEV is
deliberately over-represented (10% of the pool against about 0.5% of the source population) so KEV-first queues have
KEV entries to pick.

**Planners** (budget 3 fixes, k = 100 enumerated paths):

| planner | rule |
| --- | --- |
| LINCHPIN | exact minimum vertex cut when it fits the budget, otherwise greedy set cover of the enumerated paths |
| LINCHPIN greedy only | the set cover alone |
| Exact interdiction MILP | Israeli & Wood (2002): maximise the attacker's cheapest-path cost after at most 3 removals (HiGHS) |
| Greedy interdiction | Guo et al.-style: repeatedly remove the node on the cheapest path whose removal raises its cost most |
| Best patch-only plan | LINCHPIN's planner restricted to vulnerabilities (exact cut over vulns when it fits the budget, else greedy over vulns): the like-for-like ceiling for the score queues, which may also only patch |
| CVSS / EPSS / KEV-then-EPSS | highest score first, over all vulnerabilities |
| ... on-path only | the same queues restricted to vulnerabilities on an entry-to-crown-jewel route |
| Betweenness, random | highest cost-weighted betweenness among remediable nodes; 3 nodes drawn uniformly from all remediable nodes (vulns, credentials, ACEs, non-entry hosts), on an attack path or not |

The planners do not share an action space: the score queues may only patch, while LINCHPIN, the interdiction planners,
betweenness and random may also segment a host or rotate a credential. The best patch-only plan separates the two
effects.

**Metrics.** *Disconnect*: no crown jewel reachable afterwards. *Residual paths*: enumerated paths left, as a share of
those before (capped at k). *Cost gain*: rise of the attacker's cheapest-path cost on topologies that stay connected.
*Share of optimal gain*: cost gain divided by the MILP's. *Fixes needed* (ablation): how many of a planner's fixes,
in its own order, the real graph needs before it is disconnected, relative to the exact optimum.

**Statistics.** 95% Wilson intervals for rates; seeded percentile bootstrap (2,000 replicates) for means, not shown
when fewer than 10 topologies contribute; exact two-sided McNemar tests for paired disconnect outcomes on the same
topologies; for paired cost gains, a bootstrap interval of the mean difference over the topologies and an exact sign
test. p-values are printed as "p < 1e-4" or with three significant digits.

**Provenance.** Each result file records the commit (and whether code had uncommitted changes) or the CI run that
produced it. The benchmark and ablation tables below are the artefacts of the manual `results` workflow, run
[37089520295](https://github.com/rakshit-737/linchpin/actions/runs/37089520295) at commit 0c72593 on a Linux runner;
every outcome cell (all columns except the millisecond timings) equals the v1.1.0 run on Windows.

!!! note "What the 100% means"
    LINCHPIN plans on the same graph it is scored on, and it returns the exact minimum cut whenever that cut fits the
    budget, so its disconnect rate is 100% by construction wherever a 3-fix cut exists (all of `single`, `multi` and
    `ad`). The benchmark measures how far *other* planners are from that optimum inside LINCHPIN's attack-graph
    model, not real-world risk; the ablation measures what happens when the planner's data is incomplete.

## Synthetic benchmark

![strategies](img/results/strategies.png)

--8<-- "benchmarks/results/summary.md"

## Ablation

--8<-- "benchmarks/results/ablation.md"

## Measured case study (CI lab scan)

The `lab-scan` CI job starts official Docker images pinned to older releases (httpd 2.4.49, nginx 1.16.1,
tomcat 9.0.30, redis 5.0.7, mysql 5.5.62) on two networks created with `--internal`, so nothing in them can reach the
internet or the runner's other networks. A scanner container inside each network runs `nmap -sV` (service/version
detection only; no NSE scripts, no exploitation) against those containers alone. `benchmarks/lab_case_study.py`
derives hosts, segments and firewall rules from the measurement (`app` is the only container on both networks),
declares the two facts a scan cannot see (the `lp-dmz` network faces the internet; `db` holds the crown jewel), maps
the detected versions to CVEs offline and plans. The job fails if any check below fails. The scans, the derived
topology, the analysis and the pulled image digests below are the artefact of CI run
[37091866743](https://github.com/rakshit-737/linchpin/actions/runs/37091866743) (`lab_case_study.json` records the run
id and commit); replay with `python benchmarks/lab_case_study.py --scans benchmarks/results/lab` or
`linchpin scenario scenarios/lab_scan.yaml --data-dir .`.

--8<-- "benchmarks/results/lab/lab_case_study.md"

A version banner is not proof of exposure: backported fixes and configuration are invisible to it, so the CVE lists
are an upper bound and the plan is "upgrade these services", not a claim that each CVE is exploitable in the lab.

## Real-export case study (declared topology)

Real findings and intel (an OpenVAS scan of Metasploitable 2, a Greenbone report of a Windows Server 2019 host, a
Nessus scan of `testphp.vulnweb.com`, two nmap exports, and the SharpHound `TESTLAB.LOCAL` collection including its
ACEs), placed into a **declared** topology (`scenarios/composite_lab.yaml`) because the public exports come from
unrelated networks. Crown jewel: the NTDS database on the domain controller.

--8<-- "benchmarks/results/case_study.md"

## Reproduction: EPSS vs CVSS (Jacobs et al. 2023)

--8<-- "benchmarks/results/repro_epss.md"

**Reading: a partial replication with public data.** The paper's population is about 191k CVEs: 118,087 with an NVD
CVSS v3 score plus 73,327 v2-only CVEs whose v3 vectors the authors imputed with their own model (p. 4); CVSS 7+ is
"58.1% or 110,000 of all published CVEs" (p. 8). We can rebuild only the part that has an NVD v3 score: 117,141 CVEs
published by 2022-12-01. On it, with the EPSS scores actually published on that date (model v2022.01.01, i.e. EPSS
v2) and KEV as the label, effort reproduces within 2 points in all four rows (58.2% vs 58.1% for CVSS 7+, 40.8% vs
39.0% for EPSS at CVSS 7+ coverage, 15.0% vs 15.1% for CVSS 9.1+, 15.1% vs 15.4% for EPSS at CVSS 9.1+ effort) and
coverage within 1.5-7.5 points (CVSS 7+ 89.6% vs 82.1%; the EPSS row is matched to our own ~90% CVSS 7+ coverage, not
the paper's 82-85%). The effort ratio at equal coverage, 0.701 [0.695, 0.824], does not include the paper's EPSS v2
value 0.671. Efficiency does not reproduce (1.6% vs 8.9%; 3.4% vs 18.5%) because KEV (854 positives) is a much
sparser label than the paper's exploitation telemetry. The paper's headline "one-eighth of the effort" uses EPSS v3,
which was not published before March 2023 and cannot be scored retroactively from public data. The paper documents
KEV as an input feature of EPSS v3 (Table 1, Fig. 7); for the v2 scores used here that is likely but not documented,
so scoring EPSS against KEV on the scoring date may be circular. Against the 62 CVEs added to KEV in the following
year (a prospective label), EPSS at CVSS 9.1+'s effort covers 33 and CVSS 9.1+ 18 of the same 62: 20 vs 5
discordant, exact McNemar p = 0.0041, a difference of +24.2 points with a paired bootstrap interval of [9.7, 38.7].
The two marginal Wilson intervals ([41, 65] vs [19, 41]) overlap, which is why the paired test is the right
comparison. LINCHPIN's own exploitability blend is a worse global ranker than EPSS (68.8% effort for CVSS 7+
coverage): its job is the edge cost inside a path, not global triage. Every transcribed paper cell was checked
against the arXiv v2 PDF ([record](https://github.com/rakshit-737/linchpin/blob/main/benchmarks/results/repro_epss_paper_check.md)).

## Learned exploitability (M11)

--8<-- "benchmarks/results/ml_exploitability.md"

### Paired test against CVSS

--8<-- "benchmarks/results/ml_paired.md"

## Neo4j GDS cross-check

The `neo4j-gds` CI job loads seeded `single` topologies into Neo4j 5.26.31 Community with the Graph Data Science
2.13.13 plugin (the official image's entrypoint fetches the jar from Neo4j's plugin host), runs
`gds.shortestPath.yens` from the entry point to the crown jewel, and compares with the NetworkX engine on the same
graph. Each backend is timed 10 times, interleaved (`benchmarks/results/gds_crosscheck.json`, CI run
[37091866743](https://github.com/rakshit-737/linchpin/actions/runs/37091866743), which the file records). Costs and the
paths strictly cheaper than the k-th agree in every case; the job fails if the plugin is missing.

| hosts | nodes / relationships | k | Yen in NetworkX, median [IQR] | Yen in GDS, median [IQR] | speed-up (medians) | mirror into Neo4j |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 250 | 1,131 / 60,040 | 10 | 0.097 s [0.096, 0.098] | 0.020 s [0.016, 0.096] | 4.8x | 7.4 s |
| 250 | 1,131 / 60,040 | 100 | 0.501 s [0.495, 0.539] | 0.062 s [0.054, 0.168] | 8.1x | 5.1 s |
| 500 | 2,246 / 238,665 | 10 | 0.441 s [0.387, 0.448] | 0.011 s [0.011, 0.017] | 39x | 15.3 s |
| 500 | 2,246 / 238,665 | 100 | 1.803 s [1.746, 1.853] | 0.147 s [0.047, 0.225] | 12x | 15.4 s |

GDS timings are noisy on a shared runner (wide interquartile ranges). Across the four CI runs that measured the same
sweep (36999203784 and 37016226342 with 3 repeats, 37089503898 and 37091866743 with 10), the median speed-up per
setting ranged from 1.4x to 39x and mirroring took 5-23 s. GDS only pays off when the graph already lives in Neo4j:
mirroring it costs more than the NetworkX computation it replaces.

## Performance

![scale](img/results/scale.png)

Build + rank (k=10) + optimise (budget 5, k=100), median of 5 runs on an idle laptop (i5-13500H, Python 3.14):
1.10 s at 467 nodes / 9.8k edges (`single`) and 0.92 s at 373 nodes (`ad`), so the spec's "< 5 s at 500 nodes" holds;
3.1 s at 903 nodes, 7.0 s at 1,384 nodes / 89k edges. The optimiser time includes one exact min cut; a standalone
min cut takes 0.2-1.6 s in this range. These are one session's medians (`benchmarks/results/scale.json`, committed in
bbf492e, with the platform and command); laptop timings vary between sessions, and no other session's raw timings are
committed, so no figure for that variation is given.

## Threats to validity

* **Synthetic families are the project's own.** Their structure (bastions, parallel pivots, flat networks, AD tiers)
  decides how often a small cut exists. Results transfer to real networks only as far as these shapes do.
* **Scored inside the model.** Disconnection and cost are computed on LINCHPIN's attack graph with its edge costs;
  a real attacker is not bound by them. The ablation and the measured lab partly address this, the declared case
  study does not.
* **The identity result is designed into the families.** Only `ad` and `multi` route through cached credentials
  (by construction of the generator), so "without identity data 5/100" is a statement about those families inside the
  model, and the pooled 37% depends on the family mix. The real-export case study repeats the comparison on real data
  (one topology).
* **Planted distractors** inflate how badly the plain score queues do; the on-path variants remove that advantage. The
  action spaces still differ (queues only patch), so the best patch-only plan (95% [90, 97]) is the like-for-like
  ceiling for them.
* **Exploit-intel costs are scored with themselves.** The uniform-cost ablation plans without CVSS / EPSS / KEV but is
  scored with them, which favours the fused planner (+0.144 [0.119, 0.168] on `none`); scored with uniform costs the
  order reverses (-0.054 [-0.082, -0.027]). Neither scoring is ground truth, so the ablation does not show that exploit
  intel improves plans against a real attacker.
* **KEV is a proxy label** (for the reproduction and M11): a small, curated subset of exploitation in the wild.
* **The reproduction covers part of the paper's population** (117,141 of about 191k CVEs; the paper imputed v3 vectors
  for 73,327 v2-only CVEs) with a different label, so it is a partial replication.
* **The measured lab is small** (5 containers, 2 networks) and its CVE lists come from version banners.
* **Residual paths are capped at k**, so the residual metric saturates on dense graphs; disconnect rate and cost gain
  do not.
