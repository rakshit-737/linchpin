Findings: 135 from 6 real exports; 43/69 vuln findings carry a CVE found in NVD (the rest are CVE-less checks) (EPSS 2026-09-25), 2 in CISA KEV.
Attack graph: 128 nodes, 224 edges; 69 vuln nodes of which 33 grant code execution; 200 crown-jewel paths enumerated (k cap 200); cheapest path cost 0.422.
Single-node chokepoints: vuln:NVT-836484@app-win:42, host:app-win, cred:svc_deploy, host:win10.testlab.local, cred:ADMINISTRATOR@TESTLAB.LOCAL. Exact min cut: ['cred:ADMINISTRATOR@TESTLAB.LOCAL'].

| strategy (budget 3) | fixes chosen | crown jewel cut off? | residual paths |
| --- | --- | :---: | ---: |
| linchpin | `cred:ADMINISTRATOR@TESTLAB.LOCAL` | yes | 0 |
| cvss | `vuln:NESSUS-58987@web-php:80`<br>`vuln:NVT-100111@msf2:512`<br>`vuln:NVT-103549@msf2:1524` | no | 200 |
| epss | `vuln:NVT-111012@msf2:5432`<br>`vuln:NESSUS-58988@web-php:80`<br>`vuln:NVT-103482@msf2:80` | no | 200 |
| kev_epss | `vuln:NESSUS-58988@web-php:80`<br>`vuln:NVT-103482@msf2:80`<br>`vuln:NVT-111012@msf2:5432` | no | 200 |
| betweenness | `vuln:NESSUS-58987@web-php:80`<br>`vuln:NVT-836484@app-win:42`<br>`host:app-win` | yes | 0 |

LINCHPIN rationale for its first fix:

> Credential ADMINISTRATOR@TESTLAB.LOCAL is recoverable on win10.testlab.local and grants admin on 4 host(s) (primary.testlab.local, testmsa.testlab.local, uccomp.testlab.local, win10.testlab.local); rotate credential ADMINISTRATOR@TESTLAB.LOCAL (remove cached copies) breaks 200/200 enumerated attack paths to ds:ntds@primary.testlab.local.

Ablation, M11 learned exploitability instead of CVSS/EPSS/KEV: first fix `cred:ADMINISTRATOR@TESTLAB.LOCAL`, cheapest path cost 0.651.
Ablation, scanner scores only (no NVD/EPSS/KEV enrichment): first fix `cred:ADMINISTRATOR@TESTLAB.LOCAL`, cheapest path cost 0.428, 28 vulns granting code execution.
