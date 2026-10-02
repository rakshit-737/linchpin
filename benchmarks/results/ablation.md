Budget 3 fixes, 50 seeds per family. Each planner runs the same optimiser on a degraded view of the findings; its plan is scored on the **full** ground-truth graph. Cells: share of topologies where the crown jewel is cut off, 95% Wilson interval, and the exact McNemar p-value of the paired difference to the fused planner (omitted when the two never differ). The fused planner plans on the very graph it is scored on, so its 100% is guaranteed whenever the exact min cut fits the budget (max-flow / min-cut); the evidence is how far each degraded view falls short of it.

| planner (view of the data) | ad | multi | none | single | pooled (ad+multi+single, n=150) |
| --- | ---: | ---: | ---: | ---: | ---: |
| **LINCHPIN (fused data, exact cut)** | 100% [93%, 100%] | 100% [93%, 100%] | 0% [0%, 7%] | 100% [93%, 100%] | 100% [98%, 100%] |
| - exact cut (greedy only) | 100% [93%, 100%] | 94% [84%, 98%], p=0.25 | 0% [0%, 7%] | 100% [93%, 100%] | 98% [94%, 99%], p=0.25 |
| - identity data (scanner + firewall view) | 10% [4%, 21%], p=<1e-4 | 0% [0%, 7%], p=<1e-4 | 0% [0%, 7%] | 100% [93%, 100%] | 37% [29%, 45%], p=<1e-4 |
| - 10% of identity findings | 100% [93%, 100%] | 100% [93%, 100%] | 0% [0%, 7%] | 100% [93%, 100%] | 100% [98%, 100%] |
| - 25% of identity findings | 86% [74%, 93%], p=0.016 | 100% [93%, 100%] | 0% [0%, 7%] | 100% [93%, 100%] | 95% [91%, 98%], p=0.016 |
| - 50% of identity findings | 74% [60%, 84%], p=0.00024 | 96% [87%, 99%], p=0.5 | 0% [0%, 7%] | 100% [93%, 100%] | 90% [84%, 94%], p=<1e-4 |
| - segmentation data (flat network assumed) | 100% [93%, 100%] | 100% [93%, 100%] | 0% [0%, 7%] | 100% [93%, 100%] | 100% [98%, 100%] |
| - exploit semantics (every CVE = RCE) | 100% [93%, 100%] | 100% [93%, 100%] | 0% [0%, 7%] | 100% [93%, 100%] | 100% [98%, 100%] |
| - exploit intel (uniform edge costs) | 100% [93%, 100%] | 100% [93%, 100%] | 0% [0%, 7%] | 100% [93%, 100%] | 100% [98%, 100%] |
| identity data only (BloodHound-style view) | 54% [40%, 67%], p=<1e-4 | 0% [0%, 7%], p=<1e-4 | 0% [0%, 7%] | 0% [0%, 7%], p=<1e-4 | 18% [13%, 25%], p=<1e-4 |
| no graph: KEV then EPSS queue | 2% [0%, 10%], p=<1e-4 | 2% [0%, 10%], p=<1e-4 | 0% [0%, 7%] | 4% [1%, 13%], p=<1e-4 | 3% [1%, 7%], p=<1e-4 |

`none` has a mean exact min cut of about 7 fixes, so no 3-fix plan can disconnect it; it is excluded from the pooled column, and its rows are compared by attacker cost gain below.

### Fixes needed on the real graph

Each planner again with a generous budget (12): how many of its fixes, taken in its own order, the *real* graph needs before every crown jewel is cut off, as a multiple of the exact minimum cut (1.00 = optimal; mean with 95% bootstrap interval). "never" = share of topologies its plan does not disconnect at all. Views that over-approximate the network (flat, every CVE = RCE) always disconnect it eventually, because a cut of a super-graph also cuts the real graph; their cost is extra fixes.

| planner | ad (opt 1.34) | multi (opt 2) | none (opt 7.32) | single (opt 1) |
| --- | ---: | ---: | ---: | ---: |
| LINCHPIN (fused data, exact cut) | 1.00x [1.00, 1.00] | 1.00x [1.00, 1.00] | 1.00x [1.00, 1.00] | 1.00x [1.00, 1.00] |
| - exact cut (greedy only) | 1.01x [1.00, 1.03] | 1.22x [1.14, 1.31] | 1.27x [1.20, 1.35], never 4% | 1.00x [1.00, 1.00] |
| - identity data (scanner + firewall view) | 1.00x, never 90% | n/a, never 100% | 1.00x, never 98% | 1.00x [1.00, 1.00] |
| - 10% of identity findings | 1.00x [1.00, 1.00] | 1.00x [1.00, 1.00] | 1.00x [1.00, 1.00] | 1.00x [1.00, 1.00] |
| - 25% of identity findings | 1.00x [1.00, 1.00], never 14% | 1.00x [1.00, 1.00] | 1.00x [1.00, 1.00], never 80% | 1.00x [1.00, 1.00] |
| - 50% of identity findings | 1.00x [1.00, 1.00], never 26% | 1.00x [1.00, 1.00], never 4% | 1.00x, never 84% | 1.00x [1.00, 1.00] |
| - segmentation data (flat network assumed) | 1.00x [1.00, 1.00] | 1.00x [1.00, 1.00] | 1.00x [1.00, 1.00] | 1.82x [1.72, 1.92] |
| - exploit semantics (every CVE = RCE) | 1.10x [1.02, 1.20] | 1.00x [1.00, 1.00] | 1.09x [1.04, 1.14] | 1.00x [1.00, 1.00] |
| - exploit intel (uniform edge costs) | 1.00x [1.00, 1.00] | 1.00x [1.00, 1.00] | 1.00x [1.00, 1.00] | 1.00x [1.00, 1.00] |
| identity data only (BloodHound-style view) | 1.00x [1.00, 1.00], never 46% | n/a, never 100% | n/a, never 100% | n/a, never 100% |
| no graph: KEV then EPSS queue | 7.58x [6.16, 8.84], never 62% | 4.25x, never 92% | n/a, never 100% | 8.30x [6.90, 9.55], never 60% |

### Attacker cost gain where nothing disconnects

Rise of the attacker's cheapest-path cost (edge-cost units) after the 3 fixes, on topologies that stay connected (mean, 95% bootstrap interval, n).

| planner | ad | multi | none | single |
| --- | ---: | ---: | ---: | ---: |
| LINCHPIN (fused data, exact cut) | all disconnected | all disconnected | +0.193 [+0.169, +0.216] (n=50) | all disconnected |
| - exact cut (greedy only) | all disconnected | +0.307 (n=3) | +0.193 [+0.169, +0.216] (n=50) | all disconnected |
| - identity data (scanner + firewall view) | +0.098 [+0.061, +0.140] (n=45) | +0.046 [+0.024, +0.072] (n=50) | +0.142 [+0.117, +0.169] (n=50) | all disconnected |
| - 10% of identity findings | all disconnected | all disconnected | +0.193 [+0.169, +0.216] (n=50) | all disconnected |
| - 25% of identity findings | +0.109 (n=7) | all disconnected | +0.175 [+0.149, +0.200] (n=50) | all disconnected |
| - 50% of identity findings | +0.138 [+0.061, +0.203] (n=13) | +0.141 (n=2) | +0.173 [+0.149, +0.198] (n=50) | all disconnected |
| - segmentation data (flat network assumed) | all disconnected | all disconnected | +0.200 [+0.177, +0.223] (n=50) | all disconnected |
| - exploit semantics (every CVE = RCE) | all disconnected | all disconnected | +0.178 [+0.154, +0.203] (n=50) | all disconnected |
| - exploit intel (uniform edge costs) | all disconnected | all disconnected | +0.049 [+0.029, +0.069] (n=50) | all disconnected |
| identity data only (BloodHound-style view) | +0.000 [+0.000, +0.000] (n=23) | +0.000 [+0.000, +0.000] (n=50) | +0.019 [+0.009, +0.032] (n=50) | +0.000 [+0.000, +0.000] (n=50) |
| no graph: KEV then EPSS queue | +0.101 [+0.067, +0.141] (n=49) | +0.080 [+0.055, +0.108] (n=49) | +0.037 [+0.022, +0.056] (n=50) | +0.078 [+0.051, +0.113] (n=48) |

### How much the exploit intel moves the path ranking

Uniform-cost view vs real costs on the same graph: Kendall tau between the real top-100 paths' real costs and their uniform-view costs, and the overlap of the two top-10 path sets (mean, 95% bootstrap interval).

| family | Kendall tau | top-10 overlap |
| --- | ---: | ---: |
| ad | 0.51 [0.45, 0.56] | 0.50 [0.43, 0.56] |
| multi | 0.48 [0.41, 0.55] | 0.08 [0.05, 0.12] |
| none | 0.46 [0.39, 0.52] | 0.11 [0.08, 0.15] |
| single | 0.36 [0.29, 0.43] | 0.20 [0.15, 0.25] |
