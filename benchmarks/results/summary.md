Budget = 3 fixes per topology. Disconnect = no crown jewel reachable afterwards (95% Wilson interval). Residual = attack paths still enumerated (capped at k=100) as a fraction of before (mean ± s.e.). Cost gain = rise of the attacker's cheapest-path cost on topologies that stay connected (95% seeded bootstrap interval; n = such topologies; no interval when n < 10). p = exact McNemar test of the disconnect outcome against LINCHPIN on the same topologies.

**ad**: n=50, 12-60 hosts (58-225 nodes, mean 144), single-node chokepoint in 66%, mean exact min cut 1.34 fixes

| strategy | disconnect rate | p vs LINCHPIN | residual paths | attacker cost gain (still connected) | share of optimal gain | ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| LINCHPIN (exact cut, else greedy) | 100% [93%, 100%] | - | 0.00 ± 0.00 | n/a (all disconnected) | - | 1843 |
| LINCHPIN greedy set cover only | 100% [93%, 100%] | 1 | 0.00 ± 0.00 | n/a (all disconnected) | - | 1443 |
| Exact interdiction MILP (Israeli & Wood 2002) | 100% [93%, 100%] | 1 | 0.00 ± 0.00 | n/a (all disconnected) | - | 260 |
| Greedy interdiction (Guo et al.-style) | 100% [93%, 100%] | 1 | 0.00 ± 0.00 | n/a (all disconnected) | - | 45 |
| CVSS-first | 8% [3%, 19%] | <1e-4 | 0.81 ± 0.05 | +0.089 [+0.059, +0.122] (n=46) | - | 1 |
| CVSS-first, on-path vulns only | 22% [13%, 35%] | <1e-4 | 0.58 ± 0.07 | +0.120 [+0.081, +0.163] (n=39) | - | 3 |
| EPSS-first | 4% [1%, 13%] | <1e-4 | 0.83 ± 0.05 | +0.089 [+0.053, +0.130] (n=48) | - | 0 |
| EPSS-first, on-path vulns only | 20% [11%, 33%] | <1e-4 | 0.59 ± 0.06 | +0.173 [+0.127, +0.219] (n=40) | - | 4 |
| KEV then EPSS | 2% [0%, 10%] | <1e-4 | 0.84 ± 0.05 | +0.101 [+0.067, +0.141] (n=49) | - | 1 |
| KEV then EPSS, on-path vulns only | 20% [11%, 33%] | <1e-4 | 0.61 ± 0.06 | +0.190 [+0.143, +0.239] (n=40) | - | 4 |
| Betweenness | 30% [19%, 44%] | <1e-4 | 0.60 ± 0.07 | +0.087 [+0.049, +0.131] (n=35) | - | 649 |
| Random | 8% [3%, 19%] | <1e-4 | 0.86 ± 0.05 | +0.015 [+0.002, +0.031] (n=46) | - | 1 |

greedy fixes-to-disconnect / exact min cut = 1.01 (optimal in 98%); top-1 is a true chokepoint in 100% of chokepoint topologies.

**multi**: n=50, 12-60 hosts (69-317 nodes, mean 186), single-node chokepoint in 0%, mean exact min cut 2.00 fixes

| strategy | disconnect rate | p vs LINCHPIN | residual paths | attacker cost gain (still connected) | share of optimal gain | ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| LINCHPIN (exact cut, else greedy) | 100% [93%, 100%] | - | 0.00 ± 0.00 | n/a (all disconnected) | - | 5114 |
| LINCHPIN greedy set cover only | 94% [84%, 98%] | 0.25 | 0.06 ± 0.03 | +0.307 (n=3, no CI: n<10) | - | 4086 |
| Exact interdiction MILP (Israeli & Wood 2002) | 100% [93%, 100%] | 1 | 0.00 ± 0.00 | n/a (all disconnected) | - | 2346 |
| Greedy interdiction (Guo et al.-style) | 90% [79%, 96%] | 0.062 | 0.10 ± 0.04 | +0.399 (n=5, no CI: n<10) | - | 110 |
| CVSS-first | 2% [0%, 10%] | <1e-4 | 0.98 ± 0.02 | +0.067 [+0.036, +0.099] (n=49) | - | 1 |
| CVSS-first, on-path vulns only | 2% [0%, 10%] | <1e-4 | 0.98 ± 0.02 | +0.071 [+0.039, +0.103] (n=49) | - | 4 |
| EPSS-first | 2% [0%, 10%] | <1e-4 | 0.98 ± 0.02 | +0.073 [+0.048, +0.099] (n=49) | - | 1 |
| EPSS-first, on-path vulns only | 2% [0%, 10%] | <1e-4 | 0.98 ± 0.02 | +0.134 [+0.099, +0.170] (n=49) | - | 4 |
| KEV then EPSS | 2% [0%, 10%] | <1e-4 | 0.98 ± 0.02 | +0.080 [+0.055, +0.108] (n=49) | - | 1 |
| KEV then EPSS, on-path vulns only | 2% [0%, 10%] | <1e-4 | 0.98 ± 0.02 | +0.144 [+0.107, +0.184] (n=49) | - | 4 |
| Betweenness | 2% [0%, 10%] | <1e-4 | 0.98 ± 0.02 | +0.154 [+0.124, +0.187] (n=49) | - | 1236 |
| Random | 0% [0%, 7%] | <1e-4 | 1.00 ± 0.00 | +0.026 [+0.012, +0.043] (n=50) | - | 1 |

greedy fixes-to-disconnect / exact min cut = 1.22 (optimal in 62%).

**none**: n=50, 12-60 hosts (78-316 nodes, mean 196), single-node chokepoint in 0%, mean exact min cut 7.32 fixes

| strategy | disconnect rate | p vs LINCHPIN | residual paths | attacker cost gain (still connected) | share of optimal gain | ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| LINCHPIN (exact cut, else greedy) | 0% [0%, 7%] | - | 1.00 ± 0.00 | +0.193 [+0.169, +0.216] (n=50) | 0.83 [0.77, 0.88] | 2393 |
| LINCHPIN greedy set cover only | 0% [0%, 7%] | 1 | 1.00 ± 0.00 | +0.193 [+0.169, +0.216] (n=50) | 0.83 [0.77, 0.88] | 2065 |
| Exact interdiction MILP (Israeli & Wood 2002) | 0% [0%, 7%] | 1 | 1.00 ± 0.00 | +0.227 [+0.209, +0.245] (n=50) | 1.00 [1.00, 1.00] | 5039 |
| Greedy interdiction (Guo et al.-style) | 0% [0%, 7%] | 1 | 1.00 ± 0.00 | +0.192 [+0.168, +0.215] (n=50) | 0.82 [0.75, 0.89] | 61 |
| CVSS-first | 0% [0%, 7%] | 1 | 1.00 ± 0.00 | +0.021 [+0.009, +0.034] (n=50) | 0.09 [0.04, 0.15] | 1 |
| CVSS-first, on-path vulns only | 0% [0%, 7%] | 1 | 1.00 ± 0.00 | +0.025 [+0.013, +0.040] (n=50) | 0.11 [0.06, 0.17] | 5 |
| EPSS-first | 0% [0%, 7%] | 1 | 1.00 ± 0.00 | +0.044 [+0.026, +0.067] (n=50) | 0.17 [0.10, 0.25] | 0 |
| EPSS-first, on-path vulns only | 0% [0%, 7%] | 1 | 1.00 ± 0.00 | +0.084 [+0.058, +0.113] (n=50) | 0.32 [0.24, 0.42] | 5 |
| KEV then EPSS | 0% [0%, 7%] | 1 | 1.00 ± 0.00 | +0.037 [+0.022, +0.056] (n=50) | 0.15 [0.09, 0.22] | 2 |
| KEV then EPSS, on-path vulns only | 0% [0%, 7%] | 1 | 1.00 ± 0.00 | +0.089 [+0.064, +0.118] (n=50) | 0.35 [0.26, 0.45] | 5 |
| Betweenness | 0% [0%, 7%] | 1 | 1.00 ± 0.00 | +0.025 [+0.012, +0.040] (n=50) | 0.10 [0.05, 0.16] | 1292 |
| Random | 0% [0%, 7%] | 1 | 1.00 ± 0.00 | +0.002 [+0.000, +0.007] (n=50) | 0.01 [0.00, 0.02] | 1 |

greedy fixes-to-disconnect / exact min cut = 1.29 (optimal in 22%).

**single**: n=50, 12-60 hosts (65-290 nodes, mean 170), single-node chokepoint in 100%, mean exact min cut 1.00 fixes

| strategy | disconnect rate | p vs LINCHPIN | residual paths | attacker cost gain (still connected) | share of optimal gain | ms |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| LINCHPIN (exact cut, else greedy) | 100% [93%, 100%] | - | 0.00 ± 0.00 | n/a (all disconnected) | - | 2265 |
| LINCHPIN greedy set cover only | 100% [93%, 100%] | 1 | 0.00 ± 0.00 | n/a (all disconnected) | - | 1944 |
| Exact interdiction MILP (Israeli & Wood 2002) | 100% [93%, 100%] | 1 | 0.00 ± 0.00 | n/a (all disconnected) | - | 2155 |
| Greedy interdiction (Guo et al.-style) | 100% [93%, 100%] | 1 | 0.00 ± 0.00 | n/a (all disconnected) | - | 42 |
| CVSS-first | 2% [0%, 10%] | <1e-4 | 0.98 ± 0.02 | +0.048 [+0.023, +0.081] (n=49) | - | 1 |
| CVSS-first, on-path vulns only | 6% [2%, 16%] | <1e-4 | 0.94 ± 0.03 | +0.053 [+0.027, +0.087] (n=47) | - | 4 |
| EPSS-first | 4% [1%, 13%] | <1e-4 | 0.96 ± 0.03 | +0.075 [+0.047, +0.110] (n=48) | - | 0 |
| EPSS-first, on-path vulns only | 6% [2%, 16%] | <1e-4 | 0.94 ± 0.03 | +0.153 [+0.113, +0.197] (n=47) | - | 4 |
| KEV then EPSS | 4% [1%, 13%] | <1e-4 | 0.96 ± 0.03 | +0.078 [+0.051, +0.113] (n=48) | - | 1 |
| KEV then EPSS, on-path vulns only | 6% [2%, 16%] | <1e-4 | 0.94 ± 0.03 | +0.171 [+0.129, +0.217] (n=47) | - | 4 |
| Betweenness | 84% [71%, 92%] | 0.0078 | 0.16 ± 0.05 | +0.083 (n=8, no CI: n<10) | - | 1112 |
| Random | 22% [13%, 35%] | <1e-4 | 0.78 ± 0.06 | +0.028 [+0.008, +0.055] (n=39) | - | 1 |

greedy fixes-to-disconnect / exact min cut = 1.00 (optimal in 100%); top-1 = planted linchpin in 100%; top-1 is a true chokepoint in 100% of chokepoint topologies.

**Pooled over ad, multi, single** (n=150; the families where a 3-fix plan can disconnect):

| strategy | disconnect rate | LINCHPIN-only / strategy-only | p |
| --- | ---: | ---: | ---: |
| LINCHPIN (exact cut, else greedy) | 100% [98%, 100%] | - | - |
| LINCHPIN greedy set cover only | 98% [94%, 99%] | 3 / 0 | 0.25 |
| Exact interdiction MILP (Israeli & Wood 2002) | 100% [98%, 100%] | 0 / 0 | 1 |
| Greedy interdiction (Guo et al.-style) | 97% [92%, 99%] | 5 / 0 | 0.062 |
| CVSS-first | 4% [2%, 8%] | 144 / 0 | <1e-4 |
| CVSS-first, on-path vulns only | 10% [6%, 16%] | 135 / 0 | <1e-4 |
| EPSS-first | 3% [1%, 8%] | 145 / 0 | <1e-4 |
| EPSS-first, on-path vulns only | 9% [6%, 15%] | 136 / 0 | <1e-4 |
| KEV then EPSS | 3% [1%, 7%] | 146 / 0 | <1e-4 |
| KEV then EPSS, on-path vulns only | 9% [6%, 15%] | 136 / 0 | <1e-4 |
| Betweenness | 39% [31%, 47%] | 92 / 0 | <1e-4 |
| Random | 10% [6%, 16%] | 135 / 0 | <1e-4 |

Residual attack paths removed by LINCHPIN beyond CVSS-first, as a share of the paths before any fix, over all 200 topologies: **69.2%** [62.7%, 75.5%] (bootstrap).

