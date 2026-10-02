"""CveIntel: compact CVE -> (CVSS, EPSS, KEV) lookup, built from the public feeds."""
from __future__ import annotations

import csv
import gzip
import logging
from dataclasses import dataclass
from pathlib import Path

from linchpin.intel.feeds import iter_nvd, load_epss, load_kev

log = logging.getLogger(__name__)

COLUMNS = ["cve", "published", "cvss_version", "cvss_base", "cvss_vector", "cvss_exploitability",
           "av", "ac", "pr", "ui", "cwe", "epss", "kev", "kev_date", "ransomware", "description"]
DEFAULT_CACHE = Path("derived") / "cve_intel.csv.gz"


@dataclass(frozen=True)
class CveRecord:
    cve: str
    cvss_base: float | None = None
    cvss_vector: str | None = None
    cvss_exploitability: float | None = None  # CVSS exploitability sub-score normalised to [0, 1]
    epss: float | None = None
    kev: bool = False
    ransomware: bool = False
    kev_date: str = ""
    published: str = ""
    av: str | None = None
    ac: str | None = None
    pr: str | None = None
    ui: str | None = None
    cwe: str = ""
    description: str = ""


def _f(x) -> float | None:
    return None if x in (None, "") else float(x)


def _b(x) -> bool:
    return x in (True, "True", "true", "1")


def _rec(r: dict) -> CveRecord:
    return CveRecord(
        cve=r["cve"], cvss_base=_f(r.get("cvss_base")), cvss_vector=r.get("cvss_vector") or None,
        cvss_exploitability=_f(r.get("cvss_exploitability")), epss=_f(r.get("epss")),
        kev=_b(r.get("kev")), ransomware=_b(r.get("ransomware")), kev_date=r.get("kev_date") or "",
        published=r.get("published") or "", av=r.get("av") or None, ac=r.get("ac") or None,
        pr=r.get("pr") or None, ui=r.get("ui") or None, cwe=r.get("cwe") or "",
        description=r.get("description") or "")


class CveIntel:
    """In-memory lookup. `CveIntel.load(path)` reads the cache written by `build`."""

    def __init__(self, records: dict[str, CveRecord] | None = None, meta: dict | None = None):
        self.records = records or {}
        self.meta = meta or {}

    def __len__(self) -> int:
        return len(self.records)

    def get(self, cve: str | None) -> CveRecord | None:
        return self.records.get(cve) if cve else None

    def rows(self):
        return self.records.values()

    @classmethod
    def build(cls, data_dir: str | Path, out: str | Path | None = None) -> CveIntel:
        d = Path(data_dir)
        epss_file = next((d / "epss").glob("epss_scores-*.csv*"))
        epss, epss_date = load_epss(epss_file)
        kev = load_kev(d / "kev" / "known_exploited_vulnerabilities.json")
        rows: list[dict] = []
        for f in sorted((d / "nvd").glob("nvdcve-2.0-*.json*")):
            for r in iter_nvd(f):
                k = kev.get(r["cve"])
                r.update(epss=epss.get(r["cve"]), kev=bool(k), kev_date=(k or {}).get("date_added", ""),
                         ransomware=bool(k and k["ransomware"]))
                rows.append(r)
        log.info("intel: %d NVD records, %d EPSS, %d KEV", len(rows), len(epss), len(kev))
        if out:
            out = Path(out)
            out.parent.mkdir(parents=True, exist_ok=True)
            with gzip.open(out, "wt", encoding="utf-8", newline="") as fh:
                fh.write(f"#epss_date={epss_date}\n")
                w = csv.DictWriter(fh, fieldnames=COLUMNS, extrasaction="ignore")
                w.writeheader()
                w.writerows(rows)
        return cls({r["cve"]: _rec(r) for r in rows},
                   {"epss_date": epss_date, "n": len(rows), "kev": len(kev)})

    @classmethod
    def load(cls, path: str | Path, only: set[str] | None = None) -> CveIntel:
        """Load the cache; `only` restricts to a CVE-id subset (much less memory)."""
        recs: dict[str, CveRecord] = {}
        meta: dict = {}
        opener = gzip.open if str(path).endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8", newline="") as fh:
            first = fh.readline()
            if first.startswith("#epss_date="):
                meta["epss_date"] = first.strip().split("=", 1)[1]
                reader = csv.DictReader(fh)
            else:
                reader = csv.DictReader(fh, fieldnames=next(csv.reader([first])))
            for r in reader:
                if only is None or r["cve"] in only:
                    recs[r["cve"]] = _rec(r)
        meta["n"] = len(recs)
        return cls(recs, meta)
