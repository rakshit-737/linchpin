# Test fixtures (provenance)

| file | origin | licence |
| --- | --- | --- |
| `nmap_sample.xml` | hand-written | MIT (this repo) |
| `openvas_sample.xml` | 4 results trimmed from DefectDojo `unittests/scans/openvas/many_vuln.xml` (OpenVAS scan of Metasploitable 2) @ `a8fd87f` | BSD-3-Clause |
| `nessus_sample.nessus` | 1 ReportItem trimmed from DefectDojo `unittests/scans/tenable/nessus/nessus_with_cvssv3.nessus` (scan of testphp.vulnweb.com) @ `a8fd87f` | BSD-3-Clause |
| `nmap_vulners.xml` | DefectDojo `unittests/scans/nmap/nmap_script_vulners.xml` @ `a8fd87f` | BSD-3-Clause |
| `bloodhound/*.json` | SpecterOps BloodHound `cmd/api/src/test/fixtures/fixtures/v6/ingest/` @ `ca1be93` | Apache-2.0 |
| `intel/*` | 3 NVD records, 3 EPSS rows, 1 KEV row, abridged | public domain / FIRST terms |
| `scenario_mini.yaml` | hand-written topology over the fixtures above | MIT |
| `lab/networks.json`, `lab/scan-lp-*.xml` | hand-written in the shape of the CI lab's `docker network inspect` and `nmap -sV -oX` output (lab/scan.sh); the measured scans are in `benchmarks/results/lab/` | MIT (this repo) |
