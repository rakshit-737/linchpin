"""Build the offline CPE -> CVE index used to map scanner-detected versions to CVEs.

    python scripts/build_cpe_index.py --data-dir ../../datasets/linchpin

Reads the local NVD CVE 2.0 feeds (``nvd/``) and the intel cache (``derived/cve_intel.csv.gz``,
for CVSS / EPSS / KEV) and writes ``src/linchpin/intel/data/cpe_index.csv.gz`` (~110 kB): one row per
vulnerable ``cpeMatch`` of the products in PRODUCTS, with its exact version or version range,
joined with the CVE's CVSS base score / vector / exploitability sub-score, EPSS and KEV status.
The header comment records the source feeds' timestamps and SHA-256 hashes, so a CI job that
maps an nmap scan to CVEs needs no network access beyond the image registry.

Rows from configurations that only apply on a specific platform (an ``AND`` node such as
"redis on Debian", e.g. CVE-2022-0543) are kept but flagged ``conditional=1``; the matcher
ignores them unless asked, because LINCHPIN cannot see the platform packaging from a banner.
"""
from __future__ import annotations

import argparse
import csv
import gzip
import hashlib
import io
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from linchpin.connectors._common import impact_class
from linchpin.intel import CveIntel

# NVD vendor:product pairs covered by the index (what the CI lab runs, plus common services).
PRODUCTS = {
    "apache:http_server", "apache:tomcat", "f5:nginx", "nginx:nginx", "redis:redis", "redislabs:redis",
    "oracle:mysql", "mysql:mysql", "oracle:mysql_server", "postgresql:postgresql", "openbsd:openssh",
    "mariadb:mariadb",
}
FIELDS = ["vendor", "product", "cve", "version", "start_incl", "start_excl", "end_incl", "end_excl", "conditional",
          "cvss_base", "cvss_vector", "cvss_exploitability", "epss", "kev", "impact_class"]


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _matches(cfg: dict):
    """Yield (cpeMatch, conditional) for every vulnerable match in one NVD configuration."""
    conditional = cfg.get("operator") == "AND" and len(cfg.get("nodes", [])) > 1
    for node in cfg.get("nodes", []):
        if node.get("negate"):
            continue
        for m in node.get("cpeMatch", []):
            if m.get("vulnerable"):
                yield m, conditional


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data-dir", default="../../datasets/linchpin")
    ap.add_argument("--out", default="src/linchpin/intel/data/cpe_index.csv.gz")
    a = ap.parse_args(argv)
    d = Path(a.data_dir)
    intel = CveIntel.load(d / "derived" / "cve_intel.csv.gz")
    rows, feeds = [], []
    for f in sorted((d / "nvd").glob("nvdcve-2.0-*.json.gz")):
        with gzip.open(f, "rt", encoding="utf-8") as fh:
            doc = json.load(fh)
        feeds.append(f"{f.name}@{doc.get('timestamp', '?')}:{_sha(f)[:16]}")
        for item in doc.get("vulnerabilities", []):
            c = item["cve"]
            if c.get("vulnStatus") == "Rejected":
                continue
            seen = set()
            for cfg in c.get("configurations", []):
                for m, conditional in _matches(cfg):
                    parts = m["criteria"].split(":")
                    if len(parts) < 6 or parts[2] != "a" or f"{parts[3]}:{parts[4]}" not in PRODUCTS:
                        continue
                    ver = parts[5]
                    bounds = tuple(m.get(k, "") for k in ("versionStartIncluding", "versionStartExcluding",
                                                          "versionEndIncluding", "versionEndExcluding"))
                    if ver in ("-", "") or (ver == "*" and not any(bounds)):
                        continue  # "not applicable" or "every version": too vague to match a banner
                    key = (parts[3], parts[4], ver, bounds, conditional)
                    if key in seen:
                        continue
                    seen.add(key)
                    rec = intel.get(c["id"])
                    rows.append({
                        "vendor": parts[3], "product": parts[4], "cve": c["id"], "version": ver,
                        "start_incl": bounds[0], "start_excl": bounds[1], "end_incl": bounds[2], "end_excl": bounds[3],
                        "conditional": int(conditional),
                        "cvss_base": "" if rec is None or rec.cvss_base is None else rec.cvss_base,
                        "cvss_vector": "" if rec is None else (rec.cvss_vector or ""),
                        "cvss_exploitability": "" if rec is None or rec.cvss_exploitability is None
                        else rec.cvss_exploitability,
                        "epss": "" if rec is None or rec.epss is None else round(rec.epss, 5),
                        "kev": int(bool(rec and rec.kev)),
                        "impact_class": (impact_class(rec.cvss_vector) or "") if rec else ""})
    rows.sort(key=lambda r: (r["vendor"], r["product"], r["cve"], r["version"], r["start_incl"], r["start_excl"],
                             r["end_incl"], r["end_excl"]))
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    kev_doc = json.loads((d / "kev" / "known_exploited_vulnerabilities.json").read_text(encoding="utf-8"))
    with (gzip.GzipFile(out, "wb", compresslevel=9, mtime=0) as raw,  # mtime=0: reproducible bytes
          io.TextIOWrapper(raw, encoding="utf-8", newline="") as fh):
        fh.write(f"# cpe_index built from NVD CVE 2.0 feeds; epss_date={intel.meta.get('epss_date', '')}; "
                 f"kev_catalog={kev_doc.get('catalogVersion')}; products={','.join(sorted(PRODUCTS))}\n")
        fh.write("# feeds=" + " ".join(feeds) + "\n")
        w = csv.DictWriter(fh, fieldnames=FIELDS, lineterminator="\n")
        w.writeheader()
        w.writerows(rows)
    print(f"wrote {out}: {len(rows)} rows, {len({r['cve'] for r in rows})} CVEs, {out.stat().st_size / 1e3:.0f} kB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
