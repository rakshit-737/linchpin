# Datasets

`python scripts/download_data.py` fetches about 270 MB into `../../datasets/linchpin/`, outside the repo.
Commit-addressed files are verified against SHA-256 checksums and a manifest is written for rolling feeds.
Nothing downloaded is committed. The repo holds tiny trimmed test fixtures, the derived 3,000-CVE benchmark
pool (`src/linchpin/synth/data/cve_pool.csv`, shipped in the wheel) and the static-demo snapshots (graph structure only).

| dataset | use | licence / terms |
| --- | --- | --- |
| [NVD CVE JSON 2.0](https://nvd.nist.gov/vuln/data-feeds), 2002-2026 (379,082 CVEs) | CVSS vectors, exploitability sub-scores, CWE, descriptions | US-gov public domain. *This product uses data from the NVD API but is not endorsed or certified by the NVD.* |
| [FIRST EPSS](https://www.first.org/epss/) daily scores (v2026.06.15 model) | exploitation probability | free use with attribution: Jacobs et al., *Exploit Prediction Scoring System*, FIRST |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (1,726 entries) | known-exploited floor, ML label | CC0 / public domain |
| [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) unit-test scans @ `a8fd87f` | real OpenVAS, Nessus and nmap exports | BSD-3-Clause |
| [SpecterOps BloodHound](https://github.com/SpecterOps/BloodHound) v6 ingest fixtures @ `ca1be93` | real SharpHound identity layer (sessions, local groups, ACEs) | Apache-2.0 |

## Citations

* Jacobs, J., Romanosky, S., Edwards, B., Adjerid, I., Roytman, M. *Exploit Prediction Scoring System (EPSS).* Digital Threats: Research and Practice, 2021.
* Ou, X., Govindavajhala, S., Appel, A. *MulVAL: A Logic-based Network Security Analyzer.* USENIX Security, 2005.
* Sheyner, O., Haines, J., Jha, S., Lippmann, R., Wing, J. *Automated Generation and Analysis of Attack Graphs.* IEEE S&P, 2002.
* Yen, J. Y. *Finding the K Shortest Loopless Paths in a Network.* Management Science, 1971.

This project ran no scans. All scan data are public sample reports of deliberately vulnerable targets.
