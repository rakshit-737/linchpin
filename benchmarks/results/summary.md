Budget = 3 fixes per topology. Disconnect = no crown jewel reachable afterwards. Residual = attack paths still enumerated (capped at k=100) as a fraction of before (mean ± s.e.).

**ad** — n=50, mean graph size 136 nodes, topologies with a single-node chokepoint 62%, mean exact min cut 1.38 fixes

| strategy | disconnect rate | residual paths | attacker cost gain (still connected) | ms |
| --- | ---: | ---: | ---: | ---: |
| LINCHPIN (exact+greedy) | 100% | 0.00 ± 0.00 | n/a (all disconnected) | 595 |
| LINCHPIN greedy only | 100% | 0.00 ± 0.00 | n/a (all disconnected) | 522 |
| CVSS-first | 14% | 0.71 ± 0.06 | +0.093 | 0 |
| EPSS-first | 6% | 0.83 ± 0.05 | +0.098 | 0 |
| KEV then EPSS | 4% | 0.85 ± 0.04 | +0.109 | 0 |
| Betweenness | 40% | 0.53 ± 0.07 | +0.083 | 140 |
| Random | 12% | 0.80 ± 0.05 | +0.021 | 0 |

greedy fixes-to-disconnect / exact min cut = 1.00 (optimal in 100%); top-1 is a true chokepoint in 100% of chokepoint topologies.

**multi** — n=50, mean graph size 172 nodes, topologies with a single-node chokepoint 0%, mean exact min cut 2.00 fixes

| strategy | disconnect rate | residual paths | attacker cost gain (still connected) | ms |
| --- | ---: | ---: | ---: | ---: |
| LINCHPIN (exact+greedy) | 100% | 0.00 ± 0.00 | n/a (all disconnected) | 1343 |
| LINCHPIN greedy only | 96% | 0.04 ± 0.03 | +0.462 | 1104 |
| CVSS-first | 2% | 0.98 ± 0.02 | +0.054 | 0 |
| EPSS-first | 0% | 1.00 ± 0.00 | +0.083 | 0 |
| KEV then EPSS | 0% | 1.00 ± 0.00 | +0.084 | 0 |
| Betweenness | 0% | 1.00 ± 0.00 | +0.165 | 259 |
| Random | 0% | 1.00 ± 0.00 | +0.036 | 0 |

greedy fixes-to-disconnect / exact min cut = 1.17 (optimal in 70%).

**none** — n=50, mean graph size 182 nodes, topologies with a single-node chokepoint 0%, mean exact min cut 7.08 fixes

| strategy | disconnect rate | residual paths | attacker cost gain (still connected) | ms |
| --- | ---: | ---: | ---: | ---: |
| LINCHPIN (exact+greedy) | 0% | 1.00 ± 0.00 | +0.207 | 922 |
| LINCHPIN greedy only | 0% | 1.00 ± 0.00 | +0.207 | 859 |
| CVSS-first | 0% | 1.00 ± 0.00 | +0.023 | 0 |
| EPSS-first | 0% | 1.00 ± 0.00 | +0.054 | 0 |
| KEV then EPSS | 0% | 1.00 ± 0.00 | +0.063 | 0 |
| Betweenness | 0% | 1.00 ± 0.00 | +0.046 | 306 |
| Random | 0% | 1.00 ± 0.00 | +0.019 | 0 |

greedy fixes-to-disconnect / exact min cut = 1.34 (optimal in 18%).

**single** — n=50, mean graph size 157 nodes, topologies with a single-node chokepoint 100%, mean exact min cut 1.00 fixes

| strategy | disconnect rate | residual paths | attacker cost gain (still connected) | ms |
| --- | ---: | ---: | ---: | ---: |
| LINCHPIN (exact+greedy) | 100% | 0.00 ± 0.00 | n/a (all disconnected) | 482 |
| LINCHPIN greedy only | 100% | 0.00 ± 0.00 | n/a (all disconnected) | 448 |
| CVSS-first | 4% | 0.91 ± 0.04 | +0.086 | 0 |
| EPSS-first | 4% | 0.94 ± 0.03 | +0.099 | 0 |
| KEV then EPSS | 4% | 0.94 ± 0.03 | +0.107 | 0 |
| Betweenness | 88% | 0.12 ± 0.05 | +0.030 | 152 |
| Random | 8% | 0.90 ± 0.04 | +0.029 | 0 |

greedy fixes-to-disconnect / exact min cut = 1.00 (optimal in 100%); top-1 = planted linchpin in 100%; top-1 is a true chokepoint in 100% of chokepoint topologies.

