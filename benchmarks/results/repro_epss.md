Reproduction of Jacobs et al., *Enhancing Vulnerability Prioritization* (IEEE EuroS&PW 2023 / WEIS 2023, arXiv:2302.14172), Figures 3-5. Effort = % of the population flagged; coverage = % of exploited CVEs flagged (recall); efficiency = % of flagged CVEs exploited (precision). Brackets: 95% class-stratified bootstrap interval at the fixed threshold. n/r = not reported by the paper.

### Primary: paper-like population, KEV on the scoring date as the label

published <= 2022-12-01, NVD CVSS v3.x, EPSS v2022.01.01 scores of 2022-12-01; label = in KEV on 2022-12-01 (EPSS ingests KEV: circular, optimistic). n = 117,141, exploited = 854 (base rate 0.729%).

| strategy | threshold | effort % | coverage % | efficiency % | paper (effort / coverage / efficiency) |
| --- | ---: | ---: | ---: | ---: | --- |
| CVSS 7+ | 7.0 | 58.2 [57.9, 58.5] | 89.6 [87.7, 91.3] | 1.1 [1.1, 1.1] | 58.1 / 82.1 / 3.9 (Fig. 5, 7+) |
| EPSS, coverage matched to CVSS 7+ | 0.0106 | 40.8 [40.5, 41.0] | 90.0 [88.1, 92.0] | 1.6 [1.6, 1.6] | 39.0 / 84.7 / 8.9 (Fig. 5, EPSS v2 0.012+) |
| LINCHPIN blend (no KEV floor), coverage matched | 0.3115 | 68.8 [68.5, 69.0] | 89.6 [87.3, 91.1] | 0.9 [0.9, 1.0] | n/r |
| CVSS 9.1+ | 9.1 | 15.0 [14.8, 15.2] | 31.6 [28.7, 34.7] | 1.5 [1.4, 1.7] | 15.1 / 33.5 / 6.1 (Fig. 4, 9.1+) |
| EPSS, effort matched to CVSS 9.1+ | 0.0161 | 15.1 [14.9, 15.3] | 71.4 [68.4, 74.5] | 3.4 [3.3, 3.6] | 15.4 / 69.9 / 18.5 (Fig. 4, EPSS v2 0.037+) |

Effort ratio EPSS / CVSS 7+ at equal coverage: **0.701** (paper, EPSS v3: 0.126, "one-eighth"; paper, EPSS v2: 0.671). Coverage gain of EPSS over CVSS 9.1+ at equal effort: +39.8 points (paper: +36.4 with v2, +56.9 with v3).

### Prospective: KEV additions in the following year as the label

same population minus CVEs already in KEV; label = added to KEV in (2022-12-01, 2023-12-01] (prospective, few positives). n = 116,287, exploited = 62 (base rate 0.053%).

| strategy | threshold | effort % | coverage % | efficiency % | paper (effort / coverage / efficiency) |
| --- | ---: | ---: | ---: | ---: | --- |
| CVSS 7+ | 7.0 | 57.9 [57.7, 58.2] | 77.4 [67.7, 87.1] | 0.1 [0.1, 0.1] | 58.1 / 82.1 / 3.9 (Fig. 5, 7+) |
| EPSS, coverage matched to CVSS 7+ | 0.0089 | 100.0 [100.0, 100.0] | 100.0 [100.0, 100.0] | 0.1 [0.1, 0.1] | 39.0 / 84.7 / 8.9 (Fig. 5, EPSS v2 0.012+) |
| LINCHPIN blend (no KEV floor), coverage matched | 0.3318 | 67.7 [67.5, 68.0] | 77.4 [67.7, 87.1] | 0.1 [0.1, 0.1] | n/r |
| CVSS 9.1+ | 9.1 | 14.9 [14.7, 15.1] | 29.0 [17.7, 41.9] | 0.1 [0.1, 0.1] | 15.1 / 33.5 / 6.1 (Fig. 4, 9.1+) |
| EPSS, effort matched to CVSS 9.1+ | 0.016 | 14.9 [14.7, 15.1] | 53.2 [41.9, 64.6] | 0.2 [0.1, 0.2] | 15.4 / 69.9 / 18.5 (Fig. 4, EPSS v2 0.037+) |

Effort ratio EPSS / CVSS 7+ at equal coverage: not reachable (16 of the 62 exploited CVEs scored at most 0.00885, the most common EPSS value, held by 42% of the population; matching CVSS 7+'s coverage therefore flags almost every CVE) (paper, EPSS v3: 0.126, "one-eighth"; paper, EPSS v2: 0.671). Coverage gain of EPSS over CVSS 9.1+ at equal effort: +24.2 points (paper: +36.4 with v2, +56.9 with v3).

### Secondary: every CVE to date (the v1 analysis)

every EPSS-scored CVE, EPSS v2026.06.15 of 2026-09-25, CVSS any version; label = in today's KEV (the v1 analysis). n = 379,082, exploited = 1,726 (base rate 0.455%).

| strategy | threshold | effort % | coverage % | efficiency % | paper (effort / coverage / efficiency) |
| --- | ---: | ---: | ---: | ---: | --- |
| CVSS 7+ | 7.0 | 50.7 [50.6, 50.9] | 88.8 [87.2, 90.6] | 0.8 [0.8, 0.8] | 58.1 / 82.1 / 3.9 (Fig. 5, 7+) |
| EPSS, coverage matched to CVSS 7+ | 0.0269 | 14.7 [14.6, 14.8] | 88.8 [87.5, 90.3] | 2.7 [2.7, 2.8] | 7.3 / 82.0 / 45.5 (Fig. 5, EPSS v3 0.088+) |
| LINCHPIN blend (no KEV floor), coverage matched | 0.2937 | 71.6 [71.5, 71.8] | 88.8 [87.4, 90.3] | 0.6 [0.6, 0.6] | n/r |
| CVSS 9.1+ | 9.1 | 13.6 [13.5, 13.7] | 35.4 [33.3, 38.0] | 1.2 [1.1, 1.3] | 15.1 / 33.5 / 6.1 (Fig. 4, 9.1+) |
| EPSS, effort matched to CVSS 9.1+ | 0.0291 | 13.6 [13.5, 13.7] | 87.9 [86.4, 89.5] | 3.0 [2.9, 3.0] | 15.3 / 90.4 / 24.1 (Fig. 4, EPSS v3 0.022+) |

Effort ratio EPSS / CVSS 7+ at equal coverage: **0.29** (paper, EPSS v3: 0.126, "one-eighth"; paper, EPSS v2: 0.671). Coverage gain of EPSS over CVSS 9.1+ at equal effort: +52.5 points (paper: +36.4 with v2, +56.9 with v3).

The paper's KEV-list strategy (Fig. 3: effort 0.5%, coverage 5.9%, efficiency 53.2%) has no counterpart here: with KEV as the label it would be tautological.

Provenance: EPSS history v2022.01.01 / 2022-12-01T00:00:00+0000 (sha256 4ede8cf0b188a4e1...), EPSS current v2026.06.15 / 2026-09-25T12:03:13Z, KEV catalog 2026.09.25 (2026-09-25T18:58:16.5029Z), intel cache sha256 55da128b0c4dac17...
