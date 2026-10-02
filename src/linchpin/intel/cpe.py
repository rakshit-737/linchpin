"""Offline version -> CVE matching from scanner-detected services (no NSE scripts, no APIs).

A scanner's service detection (``nmap -sV``) reports a product, a version and usually a CPE
such as ``cpe:/a:apache:http_server:2.4.49``. :class:`CpeIndex` matches that against the
version ranges NVD publishes for each CVE (``configurations[].nodes[].cpeMatch``), using an
index built offline from the local NVD feeds (``scripts/build_cpe_index.py``) and shipped as
package data with each CVE's CVSS / EPSS / KEV values. :func:`match_services` turns matched
services into ``cve`` findings, one per service (fixing it means upgrading the software), so
a scan can be analysed without any network lookup.

Limits, stated plainly: a banner version is not proof of vulnerability (backported fixes,
build options and configuration are invisible to it), configurations that only apply on a
specific platform are ignored by default, and products outside the index are not matched.
"""
from __future__ import annotations

import csv
import gzip
import re
from collections.abc import Iterable
from dataclasses import dataclass
from functools import cmp_to_key, lru_cache
from pathlib import Path

from linchpin.connectors._common import finding, rep_cve
from linchpin.models import NormalizedFinding

INDEX = Path(__file__).resolve().parent / "data" / "cpe_index.csv.gz"

# nmap / vendor CPE names -> the vendor:product pairs NVD uses for the same software
ALIASES: dict[str, tuple[str, ...]] = {
    "apache:http_server": ("apache:http_server",),
    "apache:tomcat": ("apache:tomcat",),
    "igor_sysoev:nginx": ("f5:nginx", "nginx:nginx"),
    "nginx:nginx": ("f5:nginx", "nginx:nginx"),
    "f5:nginx": ("f5:nginx", "nginx:nginx"),
    "redislabs:redis": ("redis:redis", "redislabs:redis"),
    "redis:redis": ("redis:redis", "redislabs:redis"),
    "mysql:mysql": ("oracle:mysql", "mysql:mysql", "oracle:mysql_server"),
    "oracle:mysql": ("oracle:mysql", "mysql:mysql", "oracle:mysql_server"),
    "mariadb:mariadb": ("mariadb:mariadb",),
    "postgresql:postgresql": ("postgresql:postgresql",),
    "openbsd:openssh": ("openbsd:openssh",),
}
# nmap product strings -> CPE vendor:product, for services reported without a CPE
PRODUCT_NAMES: dict[str, str] = {
    "apache httpd": "apache:http_server", "apache tomcat": "apache:tomcat", "nginx": "nginx:nginx",
    "redis key-value store": "redis:redis", "mysql": "mysql:mysql", "mariadb": "mariadb:mariadb",
    "postgresql db": "postgresql:postgresql", "openssh": "openbsd:openssh",
}
_TOKEN = re.compile(r"\d+|[a-z]+")


_POST = {"p", "pl", "patch", "post"}  # OpenSSH-style "7.4p1": after 7.4, not a pre-release
_PRE_ORDER = {"dev": 0, "a": 1, "alpha": 1, "b": 2, "beta": 2, "m": 3, "milestone": 3, "rc": 4, "cr": 4}


def _tokens(v: str) -> list[int | str]:
    return [int(t) if t.isdigit() else t for t in _TOKEN.findall((v or "").lower())]


def compare_versions(a: str, b: str) -> int:
    """-1 / 0 / 1. Numbers compare numerically; 1.0 == 1.0.0; pre-release words (rc, beta, M)
    sort before the release they precede (1.0rc1 < 1.0); patch words (p1) sort after it."""
    ta, tb = _tokens(a), _tokens(b)
    for x, y in zip(ta, tb, strict=False):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, str) and isinstance(y, str):
            kx, ky = (_PRE_ORDER.get(x, 5), x), (_PRE_ORDER.get(y, 5), y)
            return -1 if kx < ky else 1
        # number vs word at the same position: a pre-release word is older, a patch word too
        return 1 if isinstance(x, int) else -1
    longer, sign = (tb, -1) if len(tb) > len(ta) else (ta, 1)
    rest = longer[min(len(ta), len(tb)):]
    if not rest or all(t == 0 for t in rest):
        return 0
    head = next(t for t in rest if t != 0)
    if isinstance(head, str) and head not in _POST:
        return -sign  # the longer one is a pre-release of the shorter
    return sign


def version_key(v: str):
    """Sort / comparison key for :func:`compare_versions`."""
    return cmp_to_key(compare_versions)(v)


def parse_cpe(cpe: str) -> tuple[str, str, str] | None:
    """(vendor:product, version, part) from a CPE 2.2 URI (``cpe:/a:v:p:1.2``) or 2.3 string."""
    if not cpe:
        return None
    if cpe.startswith("cpe:/"):
        parts = cpe[5:].split(":")
        part, rest = parts[0], parts[1:]
    elif cpe.startswith("cpe:2.3:"):
        parts = cpe.split(":")
        part, rest = parts[2], parts[3:]
    else:
        return None
    if len(rest) < 2:
        return None
    version = rest[2] if len(rest) > 2 and rest[2] not in ("*", "-") else ""
    return f"{rest[0].lower()}:{rest[1].lower()}", version, part


@dataclass(frozen=True)
class CpeRow:
    vendor_product: str
    cve: str
    version: str
    start_incl: str
    start_excl: str
    end_incl: str
    end_excl: str
    conditional: bool
    cvss_base: float | None
    cvss_vector: str | None
    cvss_exploitability: float | None
    epss: float | None
    kev: bool
    impact_class: str | None

    def covers(self, version: str) -> bool:
        k = version_key(version)
        if self.version != "*":
            return k == version_key(self.version)
        if self.start_incl and k < version_key(self.start_incl):
            return False
        if self.start_excl and k <= version_key(self.start_excl):
            return False
        if self.end_incl and k > version_key(self.end_incl):
            return False
        return not (self.end_excl and k >= version_key(self.end_excl))


def _num(x: str) -> float | None:
    return float(x) if x not in ("", None) else None


class CpeIndex:
    """The packaged CPE -> CVE index (``scripts/build_cpe_index.py``)."""

    def __init__(self, rows: Iterable[CpeRow], meta: str = "") -> None:
        self.by_product: dict[str, list[CpeRow]] = {}
        for r in rows:
            self.by_product.setdefault(r.vendor_product, []).append(r)
        self.meta = meta

    @classmethod
    @lru_cache(maxsize=2)
    def load(cls, path: str | None = None) -> CpeIndex:
        p = Path(path) if path else INDEX
        rows: list[CpeRow] = []
        meta: list[str] = []
        body: list[str] = []
        with gzip.open(p, "rt", encoding="utf-8", newline="") as fh:
            for ln in fh:
                (meta if ln.startswith("#") else body).append(ln)
            for r in csv.DictReader(body):
                rows.append(CpeRow(
                    vendor_product=f"{r['vendor']}:{r['product']}", cve=r["cve"], version=r["version"],
                    start_incl=r["start_incl"], start_excl=r["start_excl"], end_incl=r["end_incl"],
                    end_excl=r["end_excl"], conditional=r["conditional"] == "1", cvss_base=_num(r["cvss_base"]),
                    cvss_vector=r["cvss_vector"] or None, cvss_exploitability=_num(r["cvss_exploitability"]),
                    epss=_num(r["epss"]), kev=r["kev"] == "1", impact_class=r["impact_class"] or None))
        return cls(rows, meta=" ".join(m.strip() for m in meta)[:400])

    def match(self, vendor_product: str, version: str, include_conditional: bool = False) -> list[CpeRow]:
        """Index rows (one per CVE) whose NVD version constraint covers ``version``."""
        if not version or not version_key(version):
            return []
        out: dict[str, CpeRow] = {}
        for vp in ALIASES.get(vendor_product, (vendor_product,)):
            for r in self.by_product.get(vp, []):
                if (include_conditional or not r.conditional) and r.cve not in out and r.covers(version):
                    out[r.cve] = r
        return sorted(out.values(), key=lambda r: r.cve)


def _identify(f: NormalizedFinding) -> tuple[str, str] | None:
    """(vendor:product, version) of a service finding, from its CPE or its product name."""
    cpe = parse_cpe((f.detail or {}).get("cpe", ""))
    version = (f.version or "").split(" ")[0]
    if cpe and cpe[0] in ALIASES:
        return cpe[0], cpe[1] or version
    name = (f.software or "").strip().lower()
    vp = PRODUCT_NAMES.get(name)
    return (vp, version) if vp else None


def _impact(rows: list[CpeRow]) -> str:
    """Code execution if any member is (by vector), is KEV-listed, or has no vector (conservative)."""
    classes = {("rce" if r.kev else r.impact_class) for r in rows}
    for c in ("rce", None, "local", "info"):
        if c in classes:
            return "rce" if c is None else c
    return "info"


def _driver(rows: list[CpeRow]) -> CpeRow:
    """The CVE an attacker would use: code execution by vector first, then KEV, then EPSS / CVSS."""
    pool = [r for r in rows if r.impact_class == "rce"] or [r for r in rows if r.kev] or rows
    return max(pool, key=lambda r: (r.kev, r.epss or 0.0, r.cvss_base or 0.0, r.cve))


def match_services(findings: Iterable[NormalizedFinding], index: CpeIndex | None = None,
                   include_conditional: bool = False) -> tuple[list[NormalizedFinding], dict]:
    """``cve`` findings for every service whose product version matches NVD version ranges.

    One finding per (host, port): fixing it means upgrading the software. ``detail.cves`` lists
    every matched CVE; ``cve_id`` and the CVSS / EPSS / KEV inputs of the edge cost are those
    of the *driver* (:func:`_driver`: a code-execution CVE by vector first, then KEV, then
    EPSS), so a KEV-listed denial-of-service does not floor a code-execution edge. All KEV
    members are kept in ``detail.kev_cves``; ``detail.match = "cpe-range"``.
    """
    index = index or CpeIndex.load()
    out: list[NormalizedFinding] = []
    stats = {"services": 0, "identified": 0, "matched_services": 0, "cves": 0, "kev_cves": 0, "unmatched": []}
    seen: set[tuple[str, int]] = set()  # a dual-homed host is seen from several networks
    for f in findings:
        if f.kind != "service" or f.port is None or (f.host_id, f.port) in seen:
            continue
        seen.add((f.host_id, f.port))
        stats["services"] += 1
        ident = _identify(f)
        if not ident:
            stats["unmatched"].append(f"{f.host_id}:{f.port} {f.software or '?'} {f.version or ''}".strip())
            continue
        stats["identified"] += 1
        rows = index.match(ident[0], ident[1], include_conditional)
        if not rows:
            continue
        impact = _impact(rows)
        best = _driver(rows)
        cves = [r.cve for r in rows]
        stats["matched_services"] += 1
        stats["cves"] += len(cves)
        stats["kev_cves"] += sum(r.kev for r in rows)
        product = ident[0].split(":")[1]
        out.append(finding(
            f.host_id, "cve", f"cpe:{f.port}", "cpe-match", f.observed_at, cve_id=best.cve, port=f.port,
            cvss_base=best.cvss_base, cvss_vector=best.cvss_vector, epss=best.epss, software=f.software,
            version=f.version, service=f.service,
            detail={"vuln_id": f"CPE-{ident[0].replace(':', '-')}-{ident[1]}", "cves": cves, "match": "cpe-range",
                    "product": ident[0], "detected_version": ident[1], "upgrade": f"{product} {ident[1]}",
                    "kev": best.kev, "kev_cves": [r.cve for r in rows if r.kev], "newest_cve": rep_cve(cves),
                    "cvss_exploitability": best.cvss_exploitability, "impact_class": impact,
                    "name": f"{product} {ident[1]} ({len(cves)} CVEs by NVD version range)"}))
    return out, stats
