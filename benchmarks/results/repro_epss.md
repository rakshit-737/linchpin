# EPSS-vs-CVSS prioritisation reproduction

Population: 379,082 EPSS-scored CVEs; exploited label = CISA KEV (1,726 CVEs, base rate 0.455%).

Definitions (from the paper): **coverage** = exploited CVEs that were prioritised (recall); **efficiency** = prioritised CVEs that were exploited (precision); **effort** = share of the population prioritised.

| strategy | effort % | coverage % (of KEV) | efficiency % | paper coverage % | paper efficiency % | paper effort % |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| cvss>=7 | 50.74 | 88.82 | 0.797 | 82.1 | None | 58.1 |
| cvss>=9.1 | 13.56 | 35.4 | 1.189 | 33.5 | 6.1 | None |
| epss>=0.1 | 4.55 | 73.75 | 7.375 | - | - | - |
| kev-only | 0.46 | 100.0 | 100.0 | - | - | - |
| epss>=0.0267 (=coverage cvss>=7) | 14.88 | 88.88 | 2.72 | 82.0 | None | 7.3 |
| ours>=0.2935 (=coverage cvss>=7) | 71.62 | 88.88 | 0.565 | - | - | - |

Reading: as in the paper, CVSS>=7 attains high KEV coverage only by flagging a large share of all CVEs (poor efficiency). An EPSS threshold set to the *same coverage* reaches it at far lower effort. Honest negative result: LINCHPIN's exploitability blend (`ours` = 0.6*CVSS-exploitability + 0.4*EPSS, KEV floor withheld here to avoid scoring KEV against itself) is a *worse* global CVE ranker than EPSS alone -- the CVSS-exploitability half dilutes EPSS's signal, so it needs far more effort to reach the same KEV coverage. That is expected: LINCHPIN does not claim to beat EPSS at global CVE triage; its contribution is attack-path *context* (a CVSS-10 on an unreachable host is deprioritised; see the synthetic benchmark) plus the KEV floor, not a better scalar exploit predictor. Absolute coverage is higher than the paper's because KEV is a small, high-precision exploited set rather than broad telemetry -- the reproduced result is the *ordering* of the strategies and EPSS reaching CVSS>=7 coverage at ~1/3 the effort (paper: 58.1%->7.3%; ours: 50.7%->14.9%).
