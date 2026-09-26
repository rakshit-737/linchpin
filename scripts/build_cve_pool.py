"""Derive the small, committed CVE pool used to give synthetic topologies REAL vulnerability
parameters (CVSS base/vector/exploitability sub-score, EPSS, KEV).

    python scripts/build_cve_pool.py --intel ../../datasets/linchpin/derived/cve_intel.csv.gz

Writes benchmarks/data/cve_pool.csv (seeded random sample; all numbers come from NVD / FIRST
EPSS / CISA KEV on the EPSS score date recorded in the header comment).
"""
from __future__ import annotations

import argparse
import csv
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from linchpin.connectors._common import impact_class  # noqa: E402
from linchpin.intel import CveIntel  # noqa: E402

FIELDS = ["cve", "cvss_base", "cvss_vector", "cvss_exploitability", "epss", "kev", "impact_class"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--intel", default="../../datasets/linchpin/derived/cve_intel.csv.gz")
    ap.add_argument("--out", default="benchmarks/data/cve_pool.csv")
    ap.add_argument("--n", type=int, default=3000)
    ap.add_argument("--n-kev", type=int, default=300)
    ap.add_argument("--seed", type=int, default=7)
    a = ap.parse_args(argv)
    intel = CveIntel.load(a.intel)
    rows = [r for r in intel.rows()
            if r.cvss_base is not None and r.epss is not None and r.cvss_exploitability is not None
            and r.published >= "2015"]
    rng = random.Random(a.seed)
    kev = sorted((r for r in rows if r.kev), key=lambda r: r.cve)
    rest = sorted((r for r in rows if not r.kev), key=lambda r: r.cve)
    pick = rng.sample(kev, min(a.n_kev, len(kev))) + rng.sample(rest, a.n - min(a.n_kev, len(kev)))
    pick.sort(key=lambda r: r.cve)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8") as fh:
        fh.write(f"# sampled from NVD/EPSS/KEV; epss_date={intel.meta.get('epss_date', '')}; "
                 f"population={len(rows)} CVEs (published>=2015 with CVSS+EPSS); seed={a.seed}\n")
        w = csv.DictWriter(fh, fieldnames=FIELDS)
        w.writeheader()
        for r in pick:
            w.writerow({"cve": r.cve, "cvss_base": r.cvss_base, "cvss_vector": r.cvss_vector,
                        "cvss_exploitability": r.cvss_exploitability, "epss": r.epss, "kev": int(r.kev),
                        "impact_class": impact_class(r.cvss_vector)})
    print(f"wrote {len(pick)} rows ({sum(r.kev for r in pick)} KEV) from {len(rows)} -> {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
