Detected by `nmap -sV` (no scripts): Apache Tomcat 9.0.30, Apache httpd 2.4.49, MySQL 5.5.62, Redis key-value store 5.0.7, nginx 1.16.1.

Offline NVD version-range matching: 5 of 6 services matched, 393 CVEs, 7 of them in CISA KEV. Attack graph: 23 nodes, 36 edges, 10 entry -> crown-jewel paths (k cap 100); crown jewel ds:customer-db.

| vuln node (one per service: upgrade it) | CVSS | EPSS | KEV | code execution |
| --- | ---: | ---: | :---: | :---: |
| http_server 2.4.49 (66 CVEs by NVD version range) on `web` | 9.8 | 0.99992 | yes | yes |
| tomcat 9.0.30 (76 CVEs by NVD version range) on `app` | 9.8 | 0.99927 | yes | yes |
| nginx 1.16.1 (7 CVEs by NVD version range) on `proxy` | 7.7 | 0.53461 |  | yes |
| mysql 5.5.62 (210 CVEs by NVD version range) on `db` | 9.1 | 0.82136 |  | yes |
| redis 5.0.7 (34 CVEs by NVD version range) on `cache` | 9.9 | 0.82294 |  | yes |

Chokepoints: `vuln:CPE-apache-tomcat-9.0.30@app:8080`, `vuln:CPE-mysql-mysql-5.5.62@db:3306`; exact min cut ['vuln:CPE-mysql-mysql-5.5.62@db:3306'] (one of several minimum cuts: every chokepoint above is a one-node cut). recommend() keeps the greedy pick when it is already a cut of minimum size, preferring the node on the most enumerated paths, then the node id; the MILP may return a different minimum cut of the same size.

| strategy | 1 fix: chosen | cut off? | 3 fixes: cut off? | fixes needed to cut off |
| --- | --- | :---: | :---: | ---: |
| LINCHPIN (exact cut, else greedy) | `vuln:CPE-apache-tomcat-9.0.30@app:8080` | yes | yes | 1 |
| Exact interdiction MILP (Israeli & Wood 2002) | `vuln:CPE-mysql-mysql-5.5.62@db:3306` | yes | yes | 1 |
| Greedy interdiction (Guo et al.-style) | `vuln:CPE-apache-tomcat-9.0.30@app:8080` | yes | yes | 1 |
| CVSS-first | `vuln:CPE-redislabs-redis-5.0.7@cache:6379` | no | yes | 3 |
| CVSS-first, on-path vulns only | `vuln:CPE-redislabs-redis-5.0.7@cache:6379` | no | yes | 3 |
| EPSS-first | `vuln:CPE-apache-http_server-2.4.49@web:80` | no | yes | 2 |
| EPSS-first, on-path vulns only | `vuln:CPE-apache-http_server-2.4.49@web:80` | no | yes | 2 |
| KEV then EPSS | `vuln:CPE-apache-http_server-2.4.49@web:80` | no | yes | 2 |
| KEV then EPSS, on-path vulns only | `vuln:CPE-apache-http_server-2.4.49@web:80` | no | yes | 2 |
| Betweenness | `vuln:CPE-apache-tomcat-9.0.30@app:8080` | yes | yes | 1 |

LINCHPIN's rationale for its first fix:

> tomcat 9.0.30 on app matches 76 CVEs; the one an attacker would use is CVE-2025-24813 (CVSS 9.8, EPSS 0.99927, CISA KEV). It is a step on 10 attack paths; upgrade tomcat 9.0.30 on app (76 known CVEs) breaks 10/10 enumerated attack paths to ds:customer-db.

Checks: no NSE script output in the scans: pass; >= 3 product versions detected: pass; a CISA KEV CVE was mapped: pass; crown jewel reachable before any fix: pass; LINCHPIN's plan cuts the crown jewel off within budget 3: pass; LINCHPIN never needs more fixes than a baseline: pass.

Tools: Nmap version 7.93 ( https://nmap.org ); docker 28.0.4.

Images (tag and the digest that was pulled): `httpd:2.4.49 sha256:dcba0d12e2362fb0c50ec524ae8aa1cca4a4ba7216617a57e7bbca20767e79cc`; `nginx:1.16.1 sha256:d20aa6d1cae56fd17cd458f4807e0de462caf2336f0b70b5eeb69fcaaf30dd9c`; `tomcat:9.0.30 sha256:cba009c0ef8cec83df8178cf4f4668170bdb02440e4c7c576fc397e477c715d3`; `redis:5.0.7 sha256:938ee5bfba605cc85f9f52ff95024e9a24cf5511ba6f1cbc68ec9d91a0432125`; `mysql:5.5.62 sha256:12da85ab88aedfdf39455872fb044f607c32fdc233cd59f1d26769fbf439b045`; `debian:bookworm-slim sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251`.

Scanned and analysed in CI run [37091866743](https://github.com/rakshit-737/linchpin/actions/runs/37091866743) at commit c5d7c9e6e821.
