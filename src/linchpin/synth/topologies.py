"""Benchmark topology families with REAL vulnerability parameters.

Every vuln planted here is drawn from ``benchmarks/data/cve_pool.csv`` -- a seeded sample of
real CVEs with their NVD CVSS vector / exploitability sub-score, FIRST EPSS and CISA KEV
status -- so the CVSS / EPSS / KEV baselines are ranking realistic score distributions.
(Hosts, segments and credentials are still synthetic.)

Families (``family`` argument):

* ``single`` -- one planted pivot (bastion) between DMZ and everything else.
* ``multi``  -- 2-3 parallel bastions and two independent routes into the DB tier
  (vuln + cached credential): no single-node cut, minimum cut is 2-3 nodes.
* ``none``   -- flat network: several internet-facing hosts reach the data tier directly,
  the DB exposes several exploitable services and its admin credential is cached widely.
  There is no small cut; budgets cannot disconnect it.
* ``ad``     -- tiered Active-Directory estate: phished workstations, helpdesk local-admin
  reuse, server-admin and Domain-Admin sessions cached on lower tiers, DC holds NTDS.
  Chokepoint is usually the DA credential; half the seeds add an exploitable DC service
  (e.g. a KEV-listed RCE) that removes it.

All families add high-CVSS *decoys*: unreachable hosts and non-code-execution vulns.
"""
from __future__ import annotations

import csv
import random
from functools import lru_cache
from pathlib import Path

from linchpin.models import GroundTruth, NormalizedFinding, make_finding_id

TS = "2026-01-01T00:00:00+00:00"
POOL = Path(__file__).resolve().parents[3] / "benchmarks" / "data" / "cve_pool.csv"
FAMILIES = ("single", "multi", "none", "ad")


@lru_cache(maxsize=2)
def load_pool(path: str | None = None) -> dict[str, list[dict]]:
    p = Path(path) if path else POOL
    by: dict[str, list[dict]] = {"rce": [], "info": [], "local": [], "rce_kev": []}
    if not p.exists():
        return by
    with p.open(encoding="utf-8") as fh:
        for r in csv.DictReader(line for line in fh if not line.startswith("#")):
            rec = {"cve": r["cve"], "cvss_base": float(r["cvss_base"]), "cvss_vector": r["cvss_vector"],
                   "cvss_exploitability": float(r["cvss_exploitability"]), "epss": float(r["epss"]),
                   "kev": r["kev"] == "1", "impact_class": r["impact_class"]}
            by.setdefault(rec["impact_class"], []).append(rec)
            if rec["kev"] and rec["impact_class"] == "rce":
                by["rce_kev"].append(rec)
    return by


class _B:
    """Small builder shared by the families."""

    def __init__(self, seed: int, pool: dict[str, list[dict]]):
        self.rng = random.Random(seed)
        self.pool = pool
        self.out: list[NormalizedFinding] = []

    def f(self, host: str, kind: str, key: str, **kw) -> None:
        self.out.append(NormalizedFinding(finding_id=make_finding_id(host, kind, key), host_id=host, kind=kind,
                                          source="synth", observed_at=TS, **kw))

    def host(self, h, seg, facing=False, datastores=None, os="linux"):
        self.f(h, "config", "inventory", detail={"issue": "inventory", "severity": "low", "segment": seg,
                                                   "os": os, "internet_facing": facing,
                                                   "datastores": datastores or []})

    def svc(self, h, port, name):
        self.f(h, "service", str(port), port=port, service=name, software=f"synth-{name}", version="1")

    def vuln(self, h, port, cls="rce", kev: bool | None = None, min_cvss=0.0, max_cvss=10.0) -> str:
        """Plant a real-parameter vuln of class rce|info|local; returns its vuln node id."""
        cands = self.pool.get("rce_kev" if kev else cls) or []
        cands = [r for r in cands if min_cvss <= r["cvss_base"] <= max_cvss] or cands
        if cands:
            r = self.rng.choice(cands)
        else:  # no pool available: synthetic fallback
            r = {"cve": f"CVE-2099-{self.rng.randint(10000, 99999)}", "cvss_base": round(
                self.rng.uniform(max(min_cvss, 4.0), max_cvss), 1), "cvss_vector": None,
                "cvss_exploitability": None, "epss": round(self.rng.uniform(0, 0.5), 4), "kev": bool(kev),
                "impact_class": cls}
        self.f(h, "cve", f"{r['cve']}:{port}", cve_id=r["cve"], port=port, cvss_base=r["cvss_base"],
               cvss_vector=r["cvss_vector"], epss=r["epss"],
               detail={"impact_class": r["impact_class"], "kev": r["kev"],
                       "cvss_exploitability": r["cvss_exploitability"]})
        return f"vuln:{r['cve']}@{h}:{port}"

    def cred(self, stored_on, principal, valid_on):
        self.f(stored_on, "credential", principal, detail={"principal": principal, "cred_type": "hash",
                                                            "valid_on": list(valid_on)})

    def reach(self, a, b, ports):
        self.f("net", "reachability", f"{a}->{b}",
               detail={"from_segment": a, "to_segment": b, "ports": ports, "allowed": True})

    def noise(self, hosts, port, p=0.5):
        """Non-code-execution vulns (often high CVSS): what a CVSS-sorted queue wastes effort on."""
        for h in hosts:
            if self.rng.random() < p:
                self.vuln(h, port, "info", min_cvss=6.5)

    def decoys(self, n=2):
        first = ""
        for i in range(n):
            h = f"legacy-{i:02d}"
            self.host(h, "isolated")
            self.svc(h, 8080, "http")
            v = self.vuln(h, 8080, "rce", kev=True, min_cvss=9.0)
            first = first or v
        return first


def _single(b: _B, n: int):
    n_dmz = max(2, n // 5)
    dmz = [f"web-{i:02d}" for i in range(n_dmz)]
    internal = [f"srv-{i:02d}" for i in range(max(3, n - n_dmz - 2))]
    for h in dmz:
        b.host(h, "dmz", facing=True)
        b.svc(h, 443, "https")
        b.vuln(h, 443, "rce")
    b.host("jump-01", "mgmt")
    b.svc("jump-01", 22, "ssh")
    b.vuln("jump-01", 22, "rce", max_cvss=6.9)  # modest CVSS on the real linchpin
    for h in internal:
        b.host(h, "internal", os="windows")
        b.svc(h, 445, "smb")
        if b.rng.random() < 0.6:
            b.vuln(h, 445, "rce")
    b.noise(dmz + internal, 8443, 0.4)
    b.cred(internal[0], "svc_backup", internal)
    b.cred(internal[-1], "db_admin", ["db-01"])
    b.host("db-01", "secure", datastores=[{"name": "customer-db", "sensitivity": "high"}])
    b.svc("db-01", 1433, "mssql")
    b.vuln("db-01", 1433, "rce")
    b.reach("dmz", "mgmt", [22])
    b.reach("mgmt", "internal", [])
    b.reach("internal", "secure", [1433])
    return "host:jump-01", ["host:jump-01"], ["ds:customer-db"]


def _multi(b: _B, n: int):
    k = b.rng.choice([2, 3])
    n_dmz = max(2, n // 5)
    dmz = [f"web-{i:02d}" for i in range(n_dmz)]
    jumps = [f"jump-{i:02d}" for i in range(k)]
    internal = [f"srv-{i:02d}" for i in range(max(3, n - n_dmz - k - 1))]
    for h in dmz:
        b.host(h, "dmz", facing=True)
        b.svc(h, 443, "https")
        b.vuln(h, 443, "rce")
    for j in jumps:
        b.host(j, "mgmt")
        b.svc(j, 22, "ssh")
        b.vuln(j, 22, "rce")
    for h in internal:
        b.host(h, "internal", os="windows")
        b.svc(h, 445, "smb")
        b.vuln(h, 445, "rce")
    b.noise(dmz + internal, 8443, 0.5)
    cachers = b.rng.sample(internal, k=min(len(internal), b.rng.randint(2, 4)))
    for h in cachers:
        b.cred(h, "db_admin", ["db-01"])
    b.host("db-01", "secure", datastores=[{"name": "customer-db", "sensitivity": "high"}])
    b.svc("db-01", 1433, "mssql")
    v = b.vuln("db-01", 1433, "rce")
    b.reach("dmz", "mgmt", [22])
    b.reach("mgmt", "internal", [])
    b.reach("internal", "secure", [1433])
    planted = [f"host:{j}" for j in jumps] if k == 2 else ["cred:db_admin", v]
    return "", planted, ["ds:customer-db"]


def _none(b: _B, n: int):
    n_edge = max(3, n // 3)
    edge = [f"edge-{i:02d}" for i in range(n_edge)]
    apps = [f"app-{i:02d}" for i in range(max(3, n - n_edge - 1))]
    for h in edge:
        b.host(h, "edge", facing=True)
        b.svc(h, 443, "https")
        b.vuln(h, 443, "rce")
    for h in apps:
        b.host(h, "apps")
        b.svc(h, 8080, "http")
        b.vuln(h, 8080, "rce")
    b.noise(edge + apps, 8443, 0.5)
    b.host("db-01", "data", datastores=[{"name": "customer-db", "sensitivity": "high"}])
    ports = [(1433, "mssql"), (5985, "winrm"), (3389, "rdp"), (445, "smb")]
    for port, name in ports:
        b.svc("db-01", port, name)
        b.vuln("db-01", port, "rce")
    for h in b.rng.sample(edge + apps, k=min(len(edge + apps), 4)):
        b.cred(h, f"dba_{h}", ["db-01"])  # distinct per-host secrets: rotating one does not help
    b.reach("edge", "apps", [])
    b.reach("edge", "data", [p for p, _ in ports])
    b.reach("apps", "data", [p for p, _ in ports])
    return "", [], ["ds:customer-db"]


def _ad(b: _B, n: int):
    n_ws = max(3, n // 2)
    n_srv = max(2, n // 4)
    ws = [f"ws-{i:02d}" for i in range(n_ws)]
    srv = [f"t1-{i:02d}" for i in range(n_srv)]
    for h in ws:  # phishing / exposed client software: workstations are the entrypoints
        b.host(h, "workstations", facing=b.rng.random() < 0.4, os="windows")
        b.svc(h, 445, "smb")
        if b.rng.random() < 0.5:
            b.vuln(h, 445, "local")  # local privesc: not a remote foothold
    b.f(ws[0], "config", "inventory", detail={"issue": "inventory", "severity": "low", "segment": "workstations",
                                               "os": "windows", "internet_facing": True, "datastores": []})
    for h in srv:
        b.host(h, "tier1", os="windows")
        b.svc(h, 3389, "rdp")
        if b.rng.random() < 0.5:
            b.vuln(h, 3389, "rce")
    b.noise(ws + srv, 8443, 0.5)
    for i, h in enumerate(ws):
        if i == 0 or b.rng.random() < 0.3:
            b.svc(h, 135, "rpc")
            b.vuln(h, 135, "rce")  # client-side / exposed-service foothold
    b.cred(ws[0], "helpdesk", ws)  # phished user's box caches the helpdesk local-admin (reused everywhere)
    for h in b.rng.sample(ws, k=2):
        b.cred(h, "srv_admin", srv)
    da_hosts = b.rng.sample(srv, k=min(len(srv), b.rng.randint(1, 2)))
    for h in da_hosts:
        b.cred(h, "domain_admin", ["dc-01"])
    b.host("dc-01", "tier0", os="windows", datastores=[{"name": "ntds", "sensitivity": "high"}])
    b.svc("dc-01", 445, "smb")
    planted = ["cred:domain_admin"]
    if b.rng.random() < 0.5:
        v = b.vuln("dc-01", 445, "rce", kev=True)
        planted.append(v)
    b.reach("workstations", "tier1", [3389])
    b.reach("tier1", "tier0", [445])
    b.reach("workstations", "tier0", [445])
    return ("cred:domain_admin" if len(planted) == 1 else ""), planted, ["ds:ntds"]


_FAMILY = {"single": _single, "multi": _multi, "none": _none, "ad": _ad}


def generate_family(family: str, n_hosts: int = 20, seed: int = 0, pool_path: str | None = None
                    ) -> tuple[list[NormalizedFinding], GroundTruth]:
    if family not in _FAMILY:
        raise ValueError(f"unknown family {family!r}; choose from {FAMILIES}")
    b = _B(seed * 1009 + FAMILIES.index(family), load_pool(pool_path))
    linchpin, planted, crowns = _FAMILY[family](b, max(n_hosts, 8))
    decoy = b.decoys(2)
    # de-duplicate (a builder may overwrite a host's inventory deliberately)
    uniq = {f.finding_id: f for f in b.out}
    gt = GroundTruth(linchpin=linchpin, entrypoints=["internet"], crown_jewels=crowns, decoy_high_cvss=decoy,
                     seed=seed, topology=family, planted_cut=planted)
    return list(uniq.values()), gt
