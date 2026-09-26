Budget = 3 fixes per topology. Disconnect = no crown jewel reachable afterwards. Residual = attack paths still enumerated (capped at k=100) as a fraction of before (mean ± s.e.). Brackets: 95% Wilson interval (rates) and 95% seeded bootstrap interval (cost gain).

**ad** — n=50, mean graph size 136 nodes, topologies with a single-node chokepoint 62%, mean exact min cut 1.38 fixes

| strategy | disconnect rate | residual paths | attacker cost gain (still connected) | ms |
| --- | ---: | ---: | ---: | ---: |
| LINCHPIN (exact+greedy) | 100% [93%, 100%] | 0.00 ± 0.00 | n/a (all disconnected) | 664 |
| LINCHPIN greedy only | 100% [93%, 100%] | 0.00 ± 0.00 | n/a (all disconnected) | 541 |
| CVSS-first | 14% [7%, 26%] | 0.71 ± 0.06 | +0.093 [+0.055, +0.139] | 0 |
| EPSS-first | 6% [2%, 16%] | 0.83 ± 0.05 | +0.098 [+0.064, +0.134] | 0 |
| KEV then EPSS | 4% [1%, 13%] | 0.85 ± 0.04 | +0.109 [+0.073, +0.146] | 0 |
| Betweenness | 40% [28%, 54%] | 0.53 ± 0.07 | +0.083 [+0.046, +0.127] | 275 |
| Random | 12% [6%, 24%] | 0.80 ± 0.05 | +0.021 [+0.004, +0.041] | 0 |

greedy fixes-to-disconnect / exact min cut = 1.00 (optimal in 100%); top-1 is a true chokepoint in 100% of chokepoint topologies.

**multi** — n=50, mean graph size 172 nodes, topologies with a single-node chokepoint 0%, mean exact min cut 2.00 fixes

| strategy | disconnect rate | residual paths | attacker cost gain (still connected) | ms |
| --- | ---: | ---: | ---: | ---: |
| LINCHPIN (exact+greedy) | 100% [93%, 100%] | 0.00 ± 0.00 | n/a (all disconnected) | 5364 |
| LINCHPIN greedy only | 96% [87%, 99%] | 0.04 ± 0.03 | +0.462 [+0.432, +0.491] | 4365 |
| CVSS-first | 2% [0%, 10%] | 0.98 ± 0.02 | +0.054 [+0.028, +0.084] | 0 |
| EPSS-first | 0% [0%, 7%] | 1.00 ± 0.00 | +0.083 [+0.058, +0.112] | 1 |
| KEV then EPSS | 0% [0%, 7%] | 1.00 ± 0.00 | +0.084 [+0.058, +0.114] | 1 |
| Betweenness | 0% [0%, 7%] | 1.00 ± 0.00 | +0.165 [+0.133, +0.197] | 1317 |
| Random | 0% [0%, 7%] | 1.00 ± 0.00 | +0.036 [+0.016, +0.062] | 2 |

greedy fixes-to-disconnect / exact min cut = 1.17 (optimal in 70%).

**none** — n=50, mean graph size 182 nodes, topologies with a single-node chokepoint 0%, mean exact min cut 7.08 fixes

| strategy | disconnect rate | residual paths | attacker cost gain (still connected) | ms |
| --- | ---: | ---: | ---: | ---: |
| LINCHPIN (exact+greedy) | 0% [0%, 7%] | 1.00 ± 0.00 | +0.207 [+0.187, +0.229] | 2350 |
| LINCHPIN greedy only | 0% [0%, 7%] | 1.00 ± 0.00 | +0.207 [+0.187, +0.229] | 2081 |
| CVSS-first | 0% [0%, 7%] | 1.00 ± 0.00 | +0.023 [+0.010, +0.037] | 0 |
| EPSS-first | 0% [0%, 7%] | 1.00 ± 0.00 | +0.054 [+0.036, +0.073] | 0 |
| KEV then EPSS | 0% [0%, 7%] | 1.00 ± 0.00 | +0.063 [+0.044, +0.083] | 1 |
| Betweenness | 0% [0%, 7%] | 1.00 ± 0.00 | +0.046 [+0.027, +0.065] | 908 |
| Random | 0% [0%, 7%] | 1.00 ± 0.00 | +0.019 [+0.006, +0.034] | 1 |

greedy fixes-to-disconnect / exact min cut = 1.34 (optimal in 18%).

**single** — n=50, mean graph size 157 nodes, topologies with a single-node chokepoint 100%, mean exact min cut 1.00 fixes

| strategy | disconnect rate | residual paths | attacker cost gain (still connected) | ms |
| --- | ---: | ---: | ---: | ---: |
| LINCHPIN (exact+greedy) | 100% [93%, 100%] | 0.00 ± 0.00 | n/a (all disconnected) | 2907 |
| LINCHPIN greedy only | 100% [93%, 100%] | 0.00 ± 0.00 | n/a (all disconnected) | 2587 |
| CVSS-first | 4% [1%, 13%] | 0.91 ± 0.04 | +0.086 [+0.049, +0.128] | 1 |
| EPSS-first | 4% [1%, 13%] | 0.94 ± 0.03 | +0.099 [+0.063, +0.138] | 0 |
| KEV then EPSS | 4% [1%, 13%] | 0.94 ± 0.03 | +0.107 [+0.071, +0.143] | 0 |
| Betweenness | 88% [76%, 94%] | 0.12 ± 0.05 | +0.030 [+0.003, +0.059] | 1330 |
| Random | 8% [3%, 19%] | 0.90 ± 0.04 | +0.029 [+0.012, +0.049] | 1 |

greedy fixes-to-disconnect / exact min cut = 1.00 (optimal in 100%); top-1 = planted linchpin in 100%; top-1 is a true chokepoint in 100% of chokepoint topologies.

