# Datasets & references

`python scripts/download_data.py` fetches about 270 MB into `../../datasets/linchpin/`, outside the repo.
Commit-addressed and archived files are verified against SHA-256 values before they are moved into place, NVD feeds
against the size and hash NVD publishes in each feed's `.meta` file, and a manifest records the rolling feeds.
Nothing downloaded is committed. The repo holds tiny trimmed test fixtures, the derived 3,000-CVE benchmark pool
(`src/linchpin/synth/data/cve_pool.csv`) and CPE index (`src/linchpin/intel/data/cpe_index.csv.gz`, 113 kB), both
shipped in the wheel, the static-demo snapshots (graph structure only), and the measured CI lab scans
(`benchmarks/results/lab/`, of containers started in CI).

| dataset | use | licence / terms |
| --- | --- | --- |
| [NVD CVE JSON 2.0](https://nvd.nist.gov/vuln/data-feeds), 2002-2026 (379,082 CVEs) | CVSS vectors, exploitability sub-scores, CWE, descriptions, CPE version ranges | US-gov public domain. *This product uses data from the NVD API but is not endorsed or certified by the NVD.* |
| [FIRST EPSS](https://www.first.org/epss/) daily scores of 2026-09-25 (model v2026.06.15) | exploitation probability | free use with attribution to FIRST / Empirical Security |
| FIRST EPSS archived scores of 2022-12-01 (model v2022.01.01, EPSS v2) | the Jacobs et al. 2023 reproduction | as above |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), catalog 2026.09.25 (1,726 entries) | known-exploited floor, labels | CC0 / public domain |
| [DefectDojo](https://github.com/DefectDojo/django-DefectDojo) unit-test scans @ `a8fd87f` | real OpenVAS, Nessus and nmap exports | BSD-3-Clause |
| [SpecterOps BloodHound](https://github.com/SpecterOps/BloodHound) v6 ingest fixtures @ `ca1be93` | real SharpHound identity layer (sessions, local groups, ACEs) | Apache-2.0 |
| Official Docker images httpd 2.4.49, nginx 1.16.1, tomcat 9.0.30, redis 5.0.7, mysql 5.5.62 | the measured CI lab (run only inside GitHub Actions, internal networks, version detection only) | their upstream licences |

The only scanning in this project is that CI lab: containers the job itself starts, on Docker networks created with
`--internal`, probed with `nmap -sV` (no scripts). Every other scan is a public sample report of a deliberately
vulnerable target.

## References

Attack graphs and hardening

1. O. Sheyner, J. Haines, S. Jha, R. Lippmann, J. M. Wing. Automated generation and analysis of attack graphs. *IEEE
   Symposium on Security and Privacy*, 2002, pp. 273-284. doi:10.1109/SECPRI.2002.1004377
2. C. Phillips, L. P. Swiler. A graph-based system for network-vulnerability analysis. *New Security Paradigms
   Workshop*, 1998, pp. 71-79. doi:10.1145/310889.310919
3. X. Ou, S. Govindavajhala, A. W. Appel. MulVAL: A logic-based network security analyzer. *14th USENIX Security
   Symposium*, 2005, pp. 113-128.
4. S. Noel, S. Jajodia, B. O'Berry, M. Jacobs. Efficient minimum-cost network hardening via exploit dependency graphs.
   *ACSAC*, 2003, pp. 86-95. doi:10.1109/CSAC.2003.1254313
5. L. Wang, S. Noel, S. Jajodia. Minimum-cost network hardening using attack graphs. *Computer Communications*
   29(18):3812-3824, 2006. doi:10.1016/j.comcom.2006.06.018
6. M. Albanese, S. Jajodia, S. Noel. Time-efficient and cost-effective network hardening using attack graphs. *IEEE/IFIP
   DSN*, 2012, pp. 1-12. doi:10.1109/DSN.2012.6263942
7. J. Dunagan, A. X. Zheng, D. R. Simon. Heat-ray: combating identity snowball attacks using machine learning,
   combinatorial optimization and attack graphs. *ACM SOSP*, 2009, pp. 305-320. doi:10.1145/1629575.1629605
8. M. Guo, J. Li, A. Neumann, F. Neumann, H. Nguyen. Practical fixed-parameter algorithms for defending Active
   Directory style attack graphs. *AAAI* 36(9):9360-9367, 2022. doi:10.1609/aaai.v36i9.21167
9. M. Guo, M. Ward, A. Neumann, F. Neumann, H. Nguyen. Scalable edge blocking algorithms for defending Active
   Directory style attack graphs. *AAAI* 37(5):5649-5656, 2023. doi:10.1609/aaai.v37i5.25701

Graph algorithms and optimisation

10. J. Y. Yen. Finding the K shortest loopless paths in a network. *Management Science* 17(11):712-716, 1971.
    doi:10.1287/mnsc.17.11.712
11. L. R. Ford, D. R. Fulkerson. Maximal flow through a network. *Canadian Journal of Mathematics* 8:399-404, 1956.
    doi:10.4153/CJM-1956-045-5
12. E. Israeli, R. K. Wood. Shortest-path network interdiction. *Networks* 40(2):97-111, 2002. doi:10.1002/net.10039
13. Q. Huangfu, J. A. J. Hall. Parallelizing the dual revised simplex method. *Mathematical Programming Computation*
    10(1):119-142, 2018. doi:10.1007/s12532-017-0130-5 (HiGHS)
14. A. A. Hagberg, D. A. Schult, P. J. Swart. Exploring network structure, dynamics, and function using NetworkX.
    *7th Python in Science Conference*, 2008, pp. 11-15. doi:10.25080/tcwv9851

Vulnerability prioritisation

15. J. Jacobs, S. Romanosky, B. Edwards, I. Adjerid, M. Roytman. Exploit Prediction Scoring System (EPSS). *Digital
    Threats: Research and Practice* 2(3):1-17, 2021. doi:10.1145/3436242
16. J. Jacobs, S. Romanosky, O. Suciu, B. Edwards, A. Sarabi. Enhancing vulnerability prioritization: data-driven
    exploit predictions with community-driven insights. *IEEE EuroS&P Workshops*, 2023, pp. 194-206 (presented at
    WEIS 2023; arXiv:2302.14172). doi:10.1109/EuroSPW59978.2023.00027

Statistics

17. E. B. Wilson. Probable inference, the law of succession, and statistical inference. *JASA* 22(158):209-212, 1927.
    doi:10.1080/01621459.1927.10502953
18. Q. McNemar. Note on the sampling error of the difference between correlated proportions or percentages.
    *Psychometrika* 12(2):153-157, 1947. doi:10.1007/BF02295996
19. B. Efron. Bootstrap methods: another look at the jackknife. *The Annals of Statistics* 7(1):1-26, 1979.
    doi:10.1214/aos/1176344552

Every DOI above was checked against Crossref; MulVAL against its USENIX proceedings page.
