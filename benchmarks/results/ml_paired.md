Paired comparison on the test CVEs without exploitation-status phrases (177,629 CVEs published from 2023-01-01 whose description does not report exploitation, 631 in KEV): the default learned model (reproduces the published ROC-AUC 0.836 and average precision 0.028) against the CVSS base score, both scored on the same class-stratified bootstrap resamples (1,000 replicates, seed 0).

| metric | learned | CVSS base | learned - CVSS (95% paired bootstrap) | ratio (95%) |
| --- | ---: | ---: | ---: | ---: |
| ROC-AUC | 0.836 | 0.754 | +0.082 [+0.065, +0.100] | - |
| average precision | 0.0277 | 0.0114 | +0.0163 [+0.0111, +0.0237] | 2.43x [1.90, 3.24] |

The learned model has the higher ROC-AUC in 100.0% of the replicates. Computed at commit 094ef62cc116.
