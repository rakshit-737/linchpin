Detected by `nmap -sV` (no scripts): Apache Tomcat 9.0.30, Apache httpd 2.4.49, MySQL 5.5.62, Redis key-value store 5.0.7, nginx 1.16.1.

Offline NVD version-range matching: 5 of 6 services matched, 393 CVEs, 7 of them in CISA KEV. Attack graph: 23 nodes, 36 edges, 10 entry -> crown-jewel paths (k cap 100); crown jewel ds:customer-db.

| vuln node (one per service: upgrade it) | CVSS | EPSS | KEV | code execution |
| --- | ---: | ---: | :---: | :---: |
| http_server 2.4.49 (66 CVEs by NVD version range) on `web` | 9.8 | 0.99992 | yes | yes |
| tomcat 9.0.30 (76 CVEs by NVD version range) on `app` | 9.8 | 0.99927 | yes | yes |
| nginx 1.16.1 (7 CVEs by NVD version range) on `proxy` | 7.7 | 0.53461 |  | yes |
| mysql 5.5.62 (210 CVEs by NVD version range) on `db` | 9.1 | 0.82136 |  | yes |
| redis 5.0.7 (34 CVEs by NVD version range) on `cache` | 9.9 | 0.82294 |  | yes |

Chokepoints: `vuln:CPE-apache-tomcat-9.0.30@app:8080`, `vuln:CPE-mysql-mysql-5.5.62@db:3306`; exact min cut ['vuln:CPE-mysql-mysql-5.5.62@db:3306'].

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
