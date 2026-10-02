Findings: 135 = 119 from 6 real exports + 16 from the declared topology overlay (hosts, firewall rules, one service account); 43/69 vuln findings carry a CVE found in NVD (the rest are CVE-less checks) (EPSS 2026-09-25), 2 in CISA KEV.
Attack graph: 128 nodes, 224 edges; 69 vuln nodes of which 33 grant code execution; 200 crown-jewel paths enumerated (k cap 200); cheapest path cost 0.422. 3 abusable-ACE nodes: 1 reachable from the entry points, 0 on an enumerated path to the crown jewel. 1 credential uses target hosts the declared firewall rules do not reach (scored with prerequisite_match < 1, contract v1.3).
Single-node chokepoints: vuln:NVT-836484@app-win:42, host:app-win, cred:svc_deploy, host:win10.testlab.local, cred:ADMINISTRATOR@TESTLAB.LOCAL. Exact min cut: ['cred:ADMINISTRATOR@TESTLAB.LOCAL'].

With NVD / EPSS / KEV enrichment:

| strategy (budget 3) | fixes chosen | crown jewel cut off? | residual paths (k=200) |
| --- | --- | :---: | ---: |
| LINCHPIN (exact cut, else greedy) | `cred:ADMINISTRATOR@TESTLAB.LOCAL` | yes | 0 |
| Exact interdiction MILP (Israeli & Wood 2002) | `cred:ADMINISTRATOR@TESTLAB.LOCAL`<br>`cred:svc_deploy`<br>`host:win10.testlab.local` | yes | 0 |
| Greedy interdiction (Guo et al.-style) | `cred:ADMINISTRATOR@TESTLAB.LOCAL` | yes | 0 |
| CVSS-first | `vuln:NESSUS-58987@web-php:80`<br>`vuln:NVT-100111@msf2:512`<br>`vuln:NVT-103549@msf2:1524` | no | 200 |
| CVSS-first, on-path vulns only | `vuln:NESSUS-58987@web-php:80`<br>`vuln:NVT-100111@msf2:512`<br>`vuln:NVT-103549@msf2:1524` | no | 200 |
| EPSS-first | `vuln:NVT-111012@msf2:5432`<br>`vuln:NESSUS-58988@web-php:80`<br>`vuln:NVT-103482@msf2:80` | no | 200 |
| EPSS-first, on-path vulns only | `vuln:NESSUS-58988@web-php:80`<br>`vuln:NVT-103482@msf2:80`<br>`vuln:NVT-105042@msf2:5432` | no | 200 |
| KEV then EPSS | `vuln:NESSUS-58988@web-php:80`<br>`vuln:NVT-103482@msf2:80`<br>`vuln:NVT-111012@msf2:5432` | no | 200 |
| KEV then EPSS, on-path vulns only | `vuln:NESSUS-58988@web-php:80`<br>`vuln:NVT-103482@msf2:80`<br>`vuln:NVT-105042@msf2:5432` | no | 200 |
| Betweenness | `vuln:NESSUS-58987@web-php:80`<br>`vuln:NVT-836484@app-win:42`<br>`host:app-win` | yes | 0 |

LINCHPIN rationale for its first fix:

> Credential ADMINISTRATOR@TESTLAB.LOCAL is recoverable on win10.testlab.local and grants admin on 4 host(s) (primary.testlab.local, testmsa.testlab.local, uccomp.testlab.local, win10.testlab.local); rotate credential ADMINISTRATOR@TESTLAB.LOCAL (remove cached copies) breaks 200/200 enumerated attack paths to ds:ntds@primary.testlab.local.

M11 learned exploitability instead of CVSS/EPSS/KEV: first fix `cred:ADMINISTRATOR@TESTLAB.LOCAL`, cheapest path cost 0.530.

Scanner scores only (no NVD/EPSS/KEV enrichment; 28 vulns grant code execution, cheapest path cost 0.428). Without EPSS data only findings whose export carries an EPSS value can be ranked by EPSS, which is why the EPSS queues differ:

| strategy (budget 3) | fixes chosen | crown jewel cut off? | residual paths (k=200) |
| --- | --- | :---: | ---: |
| LINCHPIN (exact cut, else greedy) | `cred:ADMINISTRATOR@TESTLAB.LOCAL` | yes | 0 |
| Exact interdiction MILP (Israeli & Wood 2002) | `cred:ADMINISTRATOR@TESTLAB.LOCAL`<br>`cred:svc_deploy`<br>`host:win10.testlab.local` | yes | 0 |
| Greedy interdiction (Guo et al.-style) | `cred:ADMINISTRATOR@TESTLAB.LOCAL` | yes | 0 |
| CVSS-first | `vuln:NESSUS-58987@web-php:80`<br>`vuln:NVT-100111@msf2:512`<br>`vuln:NVT-103549@msf2:1524` | no | 200 |
| CVSS-first, on-path vulns only | `vuln:NESSUS-58987@web-php:80`<br>`vuln:NVT-100111@msf2:512`<br>`vuln:NVT-103549@msf2:1524` | no | 200 |
| EPSS-first | `vuln:NVT-836484@app-win:42`<br>`vuln:NESSUS-11229@web-php:80`<br>`vuln:NESSUS-142591@web-php:80` | yes | 0 |
| EPSS-first, on-path vulns only | `vuln:NVT-836484@app-win:42`<br>`vuln:NESSUS-24907@web-php:80`<br>`vuln:NESSUS-25971@web-php:80` | yes | 0 |
| KEV then EPSS | `vuln:NVT-836484@app-win:42`<br>`vuln:NESSUS-58987@web-php:80`<br>`vuln:NVT-100111@msf2:512` | yes | 0 |
| KEV then EPSS, on-path vulns only | `vuln:NVT-836484@app-win:42`<br>`vuln:NESSUS-58987@web-php:80`<br>`vuln:NVT-100111@msf2:512` | yes | 0 |
| Betweenness | `vuln:NESSUS-58987@web-php:80`<br>`vuln:NVT-836484@app-win:42`<br>`host:app-win` | yes | 0 |
