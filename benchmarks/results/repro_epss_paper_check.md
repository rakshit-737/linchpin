# Check of the transcribed Jacobs et al. cells against the paper

Checked on 2026-10-03. Every value that `benchmarks/repro_epss.py` (`PAPER`) takes from the paper was compared with the PDF of
J. Jacobs, S. Romanosky, O. Suciu, B. Edwards, A. Sarabi, *Enhancing Vulnerability Prioritization: Data-Driven Exploit
Predictions with Community-Driven Insights*, arXiv:2302.14172v2 (15 Jun 2023), <https://arxiv.org/pdf/2302.14172v2>,
13 pages, sha256 `4ebdcee2e404b029cf7241ba61d6babec933efa57f158a91cf1d9c117eb1ca64`. The text of pages 7-9 was
extracted with `pdftotext -layout` (Poppler) and each figure panel was read off it. The PDF is not stored in the repo.

**Result: all 9 cells (9 thresholds, 27 percentages) match. No correction was needed.**
`tests/test_repro_epss.py` pins these values.

| key in `PAPER` | figure (page) | panel text in the PDF | transcribed: threshold, effort / coverage / efficiency % | match |
| --- | --- | --- | --- | :---: |
| `kev_list` | Fig. 3 (p. 7) | "Site:KEV Effort: 0.5% of CVEs Coverage: 5.9% Efficiency: 53.2%" | Site:KEV, 0.5 / 5.9 / 53.2 | yes |
| `cvss>=9.1` | Fig. 4 (p. 8) | "CVSS v3.x Threshold: 9.1+ Effort: 15.1% of CVEs Coverage: 33.5% Efficiency: 6.1%" | 9.1+, 15.1 / 33.5 / 6.1 | yes |
| `epss_v1_eq_effort` | Fig. 4 (p. 8) | "EPSS v1 Threshold: 0.062+ Effort: 15.1% of CVEs Coverage: 57.0% Efficiency: 15.4%" | 0.062+, 15.1 / 57.0 / 15.4 | yes |
| `epss_v2_eq_effort` | Fig. 4 (p. 8) | "EPSS v2 Threshold: 0.037+ Effort: 15.4% of CVEs Coverage: 69.9% Efficiency: 18.5%" | 0.037+, 15.4 / 69.9 / 18.5 | yes |
| `epss_v3_eq_effort` | Fig. 4 (p. 8) | "EPSS v3 Threshold: 0.022+ Effort: 15.3% of CVEs Coverage: 90.4% Efficiency: 24.1%" | 0.022+, 15.3 / 90.4 / 24.1 | yes |
| `cvss>=7` | Fig. 5 (p. 9) | "CVSS v3.x Threshold: 7+ Effort: 58.1% of CVEs Coverage: 82.1% Efficiency: 3.9%" | 7+, 58.1 / 82.1 / 3.9 | yes |
| `epss_v1_eq_cov` | Fig. 5 (p. 9) | "EPSS v1 Threshold: 0.015+ Effort: 44.3% of CVEs Coverage: 82.2% Efficiency: 7.6%" | 0.015+, 44.3 / 82.2 / 7.6 | yes |
| `epss_v2_eq_cov` | Fig. 5 (p. 9) | "EPSS v2 Threshold: 0.012+ Effort: 39.0% of CVEs Coverage: 84.7% Efficiency: 8.9%" | 0.012+, 39.0 / 84.7 / 8.9 | yes |
| `epss_v3_eq_cov` | Fig. 5 (p. 9) | "EPSS v3 Threshold: 0.088+ Effort: 7.3% of CVEs Coverage: 82.0% Efficiency: 45.5%" | 0.088+, 7.3 / 82.0 / 45.5 | yes |

The body text confirms which numbers belong to which panel: p. 8 gives KEV "half of one percent (0.5%)", "efficiency of
53.2%" and "coverage ... only 5.9%"; CVSS 9.1+ "coverage and efficiency of 33.5% and 6.1%"; EPSS v2 at 0.037 "69.9%
coverage and 18.5% efficiency"; EPSS v3 "90.4% coverage and 24.1% efficiency"; CVSS 7+ "82.1% ... 58.1% or 110,000 of
all published CVEs"; EPSS v3 at 0.088 "7.3% or just under 14,000 vulnerabilities".

Derived values used in the repo, recomputed from the cells: effort ratio at equal coverage 39.0 / 58.1 = 0.671 (EPSS v2)
and 7.3 / 58.1 = 0.126 (EPSS v3, "one-eighth"); coverage gain over CVSS 9.1+ at equal effort 69.9 - 33.5 = +36.4 points
(v2) and 90.4 - 33.5 = +56.9 points (v3).

Other statements of the paper the repo relies on, checked at the same time:

| statement | where in the PDF | consequence here |
| --- | --- | --- |
| "We collected CVSS version 3 information from NVD for 118,087 vulnerabilities. However, 73,327 vulnerabilities published before CVSSv3 ... are only scored in NVD using CVSSv2"; a separate model estimates their v3 vectors | p. 4, Sec. 3.2 | the paper's population is about 191k CVEs; ours is the 117,141 with an NVD v3 score |
| CVSS 7+ is "58.1% or 110,000 of all published CVEs"; 15% effort is "about 28,000 vulnerabilities" | pp. 8-9 | same population size, about 191k |
| v2 used XGBoost and "the feature set was greatly expanded from 16 to 1,164" | p. 2 | the v2 feature list is not given |
| Table 1 ("CVE mentioned on list or website: CISA KEV, Google Project Zero, Trend Micro ZDI") and Fig. 7 ("Site: KEV" among the top SHAP features) describe the paper's model with 1,477 features, i.e. EPSS v3 | p. 3, p. 10 | KEV as an input is documented for v3; for the v2 scores of 2022-12-01 it is likely but not documented |
