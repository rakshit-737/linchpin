# ADR 0003: Real data without a real enterprise

**Status:** accepted (v0.2)

## Context
Attack-path tools need scanner output, identity data and topology *from the same network*. No public dataset provides all three, and scanning third-party hosts is off-limits. Docker was unavailable on the build machine, so containers could not be scanned locally.

## Decision
Use three layers of realism and label each one honestly:
1. **Real exports:** public sample reports (DefectDojo's OpenVAS, Nessus and nmap test corpus; BloodHound's SharpHound fixtures), pinned by commit and SHA-256.
2. **Real exploit intel:** NVD, EPSS and KEV for every CVE, used in edge costs, baselines and the ML label.
3. **Declared topology:** a scenario YAML places the exports into one enterprise layout. It is stated as an assumption in the file header and in the README.

For statistical benchmarks, synthetic topology families draw every vuln from a committed pool of 3,000 real CVEs, so the CVSS, EPSS and KEV baselines face realistic score distributions.

## Consequences
The case study demonstrates reasoning on real finding data but is not evidence about any real organisation. The benchmark covers the zero, one and multiple chokepoint regimes.
