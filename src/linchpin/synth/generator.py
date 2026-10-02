"""M9: synthetic-enterprise generator with a ground-truth answer key.

Topology (all fictional, RFC-free hostnames; CVE ids are CVE-2099-* placeholders with random scores --
use :mod:`linchpin.synth.topologies` for real CVE parameters):

    internet -> dmz (web hosts) -> mgmt (single jump host = planted linchpin) -> internal
             -> secure (DB host holding the high-sensitivity datastore)

plus an `isolated` segment containing a CVSS 10.0 decoy that is unreachable from anywhere.
Internal hosts share a local-admin credential (lateral movement) and one caches a
DB-admin credential, so the jump host is the unique non-endpoint graph cut.
"""
from __future__ import annotations

import random

from linchpin.models import GroundTruth, NormalizedFinding, make_finding_id

TS = "2026-01-01T00:00:00+00:00"


def _f(host_id: str, kind: str, key: str, **kw) -> NormalizedFinding:
    return NormalizedFinding(finding_id=make_finding_id(host_id, kind, key), host_id=host_id,
                             kind=kind, source="synth", observed_at=TS, **kw)


def _cve(rng: random.Random) -> str:
    """Placeholder id in the CVE-2099 range, so it is never mistaken for a real CVE."""
    rng.randint(2015, 2025)  # draw kept so seeded topologies stay identical to earlier versions
    return f"CVE-2099-{rng.randint(10000, 99999)}"


def generate(n_hosts: int = 20, n_segments: int = 5, seed: int = 0
             ) -> tuple[list[NormalizedFinding], GroundTruth]:
    """n_segments is accepted for interface compatibility; the MVP always emits 5 segments."""
    rng = random.Random(seed)
    n_hosts = max(n_hosts, 8)
    n_dmz = max(2, n_hosts // 5)
    n_int = max(3, n_hosts - n_dmz - 3)  # minus jump, db, decoy
    out: list[NormalizedFinding] = []

    def inventory(h, seg, facing=False, datastores=None, os="linux"):
        out.append(_f(h, "config", "inventory", detail={
            "issue": "inventory", "severity": "low", "segment": seg, "os": os,
            "internet_facing": facing, "datastores": datastores or []}))

    def svc(h, port, name, software="synthsoft", version="1.0"):
        out.append(_f(h, "service", str(port), port=port, service=name, software=software, version=version))

    def vuln(h, port, cvss, epss):
        cve = _cve(rng)
        out.append(_f(h, "cve", f"{cve}:{port}", cve_id=cve, port=port, cvss_base=round(cvss, 1),
                      epss=round(epss, 3), detail={"exploit_maturity": "poc"}))

    def reach(a, b, ports):
        out.append(_f("net", "reachability", f"{a}->{b}",
                      detail={"from_segment": a, "to_segment": b, "ports": ports, "allowed": True}))

    dmz = [f"web-{i:02d}" for i in range(1, n_dmz + 1)]
    internal = [f"srv-{i:02d}" for i in range(1, n_int + 1)]
    jump, db, decoy = "jump-01", "db-01", "legacy-01"

    for h in dmz:
        inventory(h, "dmz", facing=True)
        svc(h, 443, "https", "synth-httpd", "2.4")
        vuln(h, 443, rng.uniform(5.0, 8.5), rng.uniform(0.05, 0.6))

    inventory(jump, "mgmt")
    svc(jump, 22, "ssh", "synth-sshd", "7.2")
    svc(jump, 3389, "rdp", "synth-rdp", "10")
    vuln(jump, 22, rng.uniform(3.5, 4.9), rng.uniform(0.2, 0.5))   # two modest CVSS-4s ...
    vuln(jump, 3389, rng.uniform(3.5, 4.9), rng.uniform(0.2, 0.5))  # ... on the linchpin

    for h in internal:
        inventory(h, "internal", os="windows")
        svc(h, 445, "smb", "synth-smb", "3.0")
        if rng.random() < 0.6:
            vuln(h, 445, rng.uniform(4.0, 9.0), rng.uniform(0.01, 0.4))
    out.append(_f(internal[0], "credential", "svc_backup", detail={
        "principal": "svc_backup", "cred_type": "hash", "valid_on": internal}))
    da_host = internal[-1]
    out.append(_f(da_host, "credential", "db_admin", detail={
        "principal": "db_admin", "cred_type": "password", "valid_on": [db]}))

    inventory(db, "secure", datastores=[{"name": "customer-db", "sensitivity": "high"}])
    svc(db, 1433, "mssql", "synth-sql", "2019")
    vuln(db, 1433, rng.uniform(5.0, 7.0), rng.uniform(0.05, 0.3))

    inventory(decoy, "isolated", datastores=[{"name": "legacy-archive", "sensitivity": "low"}])
    svc(decoy, 8080, "http", "synth-legacy", "0.9")
    decoy_cve = "CVE-2021-44228"  # well-known id used only as a label on a synthetic node
    out.append(_f(decoy, "cve", f"{decoy_cve}:8080", cve_id=decoy_cve, port=8080, cvss_base=10.0,
                  epss=0.97, detail={"exploit_maturity": "high"}))

    reach("dmz", "mgmt", [22, 3389])
    reach("mgmt", "internal", [])
    reach("internal", "secure", [1433])

    gt = GroundTruth(linchpin=f"host:{jump}", entrypoints=["internet"], crown_jewels=["ds:customer-db"],
                     decoy_high_cvss=f"vuln:{decoy_cve}@{decoy}:8080", seed=seed)
    return out, gt
