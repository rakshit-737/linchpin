"""Fetch the public datasets LINCHPIN's real-data pipeline uses (never committed to git).

Usage:  python scripts/download_data.py [--out DIR] [--years 2002-2025] [--skip-nvd]

Sources (all public, no auth):
  * CISA Known Exploited Vulnerabilities catalog (CC0 / US-gov public domain)
  * FIRST EPSS daily scores (free to use, attribution to FIRST.org / Empirical Security)
  * NVD CVE JSON 2.0 yearly feeds (US-gov public domain; "This product uses the NVD API
    but is not endorsed or certified by the NVD")
  * Sample OpenVAS / Nessus / nmap exports from DefectDojo's unit-test corpus (BSD-3-Clause),
    pinned to a commit
  * SharpHound v6 JSON ingest fixtures from SpecterOps/BloodHound (Apache-2.0), pinned

A SHA-256 manifest (`MANIFEST.sha256`) is written next to the data. Pinned (commit-addressed)
files are verified against the checksums in PINNED below; rolling feeds (KEV/EPSS/NVD) change
daily, so their hashes are recorded rather than enforced.
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import urllib.request
from pathlib import Path

DD = "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/a8fd87fc0820d5a581e16552f1407a08b5e7cccf/unittests/scans"
BH = "https://raw.githubusercontent.com/SpecterOps/BloodHound/ca1be93f3d53f1df349459f37c632fce3acb2b31/cmd/api/src/test/fixtures/fixtures/v6/ingest"

ROLLING = {
    "kev/known_exploited_vulnerabilities.json": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss/epss_scores-current.csv.gz": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
}
PINNED_URLS = {
    "scans/openvas/many_vuln.xml": f"{DD}/openvas/many_vuln.xml",
    "scans/openvas/report_detail_v2.xml": f"{DD}/openvas/report_detail_v2.xml",
    "scans/nessus/nessus_with_cvssv3.nessus": f"{DD}/tenable/nessus/nessus_with_cvssv3.nessus",
    "scans/nessus/nessus_many_vuln.xml": f"{DD}/tenable/nessus/nessus_many_vuln.xml",
    "scans/nmap/nmap_multiple_port.xml": f"{DD}/nmap/nmap_multiple_port.xml",
    "scans/nmap/nmap_script_vulners.xml": f"{DD}/nmap/nmap_script_vulners.xml",
    **{f"bloodhound/v6/{n}.json": f"{BH}/{n}.json"
       for n in ("computers", "users", "groups", "domains", "sessions", "ous", "gpos", "containers")},
}
# SHA-256 of commit-pinned files (verified on every run).
PINNED: dict[str, str] = {
    "bloodhound/v6/computers.json": "e970efba667e7d8fe4c60bcb0f211c70f450eda867725504f3a7eb89bf1ee046",
    "bloodhound/v6/containers.json": "acd82547a0dd660055325dde79e80c4379191d4683aecb1507c823705a092a73",
    "bloodhound/v6/domains.json": "02943a619ccec0710127a952a55cade7dc9c1317154dd5c520c88c415c7548d5",
    "bloodhound/v6/gpos.json": "e2ecc8fb455d94d3b09618c6725941ba773f45f30f716f71f756748556b1347e",
    "bloodhound/v6/groups.json": "4ea21724524282b59b20d5195e51b622ada523568818bcb223b8da57f4d7fd78",
    "bloodhound/v6/ous.json": "0c7955d252122ebf75fc21671b56865bef23717c852a6a0b009ae381353440dc",
    "bloodhound/v6/sessions.json": "0107ceba0247b0a77d1d18fc8d5bd429f11f7ebc9dd0d0220f5c71252c67d076",
    "bloodhound/v6/users.json": "220c659efc60cbf74f645d6a8bd5864563b10a48cee11d86f32499d29bfbf12a",
    "scans/nessus/nessus_many_vuln.xml": "9c832e248c0c6e26571f7b680e3d2dfb2d5c905d6958080dd3ed6212e8ff6280",
    "scans/nessus/nessus_with_cvssv3.nessus": "ffe0306a4ec2b33b4a0c39031fe556aa0425f1359fd7f0fef24700eb79de6928",
    "scans/nmap/nmap_multiple_port.xml": "14c3507723fa4619fe4c5e6f48a158881ffc0dc8dc6fbc42d35d30fdce0f3bc0",
    "scans/nmap/nmap_script_vulners.xml": "f9ee8cc4d133bc4a3d803e9bf47255dbf419205eaac1b53286c702cb38f9ed8e",
    "scans/openvas/many_vuln.xml": "135edfa30a4eb39bbe548d7e5f8373d2b27b5b6841b6d2506ec39fa94aee3c6b",
    "scans/openvas/report_detail_v2.xml": "3a0876e30d45f4f462c165112fc3250eb56a7fc6aaa1b81d4083f8dca118cc15",
}


def sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(url: str, dest: Path, force: bool = False) -> None:
    if dest.exists() and dest.stat().st_size > 0 and not force:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    req = urllib.request.Request(url, headers={"User-Agent": "linchpin-dataset-fetch/1.0"})
    tmp = dest.with_suffix(dest.suffix + ".part")
    with urllib.request.urlopen(req, timeout=300) as r, tmp.open("wb") as fh:  # nosec B310 - fixed https URLs
        while chunk := r.read(1 << 20):
            fh.write(chunk)
    tmp.replace(dest)
    print(f"  fetched {dest} ({dest.stat().st_size / 1e6:.1f} MB)")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="../../datasets/linchpin")
    ap.add_argument("--years", default="2002-2025")
    ap.add_argument("--skip-nvd", action="store_true")
    a = ap.parse_args(argv)
    out = Path(a.out)
    items = dict(ROLLING) | dict(PINNED_URLS)
    if not a.skip_nvd:
        y0, y1 = (int(x) for x in a.years.split("-"))
        for y in range(y0, y1 + 1):
            items[f"nvd/nvdcve-2.0-{y}.json.gz"] = f"https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{y}.json.gz"
    bad = 0
    lines = []
    for rel, url in items.items():
        dest = out / rel
        fetch(url, dest)
        digest = sha256(dest)
        want = PINNED.get(rel)
        if want and want != digest:
            print(f"CHECKSUM MISMATCH {rel}: {digest} != {want}", file=sys.stderr)
            bad += 1
        lines.append(f"{digest}  {rel}")
    (out / "MANIFEST.sha256").write_text("\n".join(lines) + "\n")
    print(f"{len(items)} files under {out}; manifest written")
    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
