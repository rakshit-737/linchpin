"""Provenance of the public feeds a result was computed from: versions, dates and hashes.

EPSS and KEV are rolling feeds and NVD records are revised, so every result file that used them
records which snapshot it saw (see benchmarks/*.py).
"""
from __future__ import annotations

import gzip
import hashlib
import json
import re
from pathlib import Path

_TIMESTAMP = re.compile(rb'"timestamp"\s*:\s*"([^"]+)"')


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _epss(p: Path) -> dict:
    opener = gzip.open if p.suffix == ".gz" else open
    with opener(p, "rt", encoding="utf-8") as fh:
        head = fh.readline().strip().lstrip("#")
    meta = dict(kv.split(":", 1) for kv in head.split(",") if ":" in kv)
    return {"file": p.name, "model_version": meta.get("model_version"), "score_date": meta.get("score_date"),
            "sha256": _sha256(p)}


def feed_provenance(data_dir: str | Path) -> dict:
    """Versions, dates and SHA-256 hashes of the feeds under ``data_dir`` (missing feeds are omitted).

    Args:
        data_dir: the folder written by ``scripts/download_data.py``.

    Returns:
        A JSON-serialisable dict with the EPSS model version and score date (current and archived),
        the KEV ``catalogVersion`` and ``dateReleased``, the NVD feed count and timestamp range, and
        the hashes of the KEV file, the intel cache and ``MANIFEST.sha256``.
    """
    d = Path(data_dir)
    out: dict = {}
    current = sorted((d / "epss").glob("epss_scores-*.csv*"))
    if current:
        out["epss"] = _epss(current[0])
    history = sorted((d / "epss" / "history").glob("epss_scores-*.csv*"))
    if history:
        out["epss_history"] = [_epss(p) for p in history]
    kev = d / "kev" / "known_exploited_vulnerabilities.json"
    if kev.exists():
        doc = json.loads(kev.read_text(encoding="utf-8"))
        out["kev"] = {"catalogVersion": doc.get("catalogVersion"), "dateReleased": doc.get("dateReleased"),
                      "count": doc.get("count"), "sha256": _sha256(kev)}
    stamps = []
    for f in sorted((d / "nvd").glob("nvdcve-2.0-*.json.gz")):
        with gzip.open(f, "rb") as fh:
            m = _TIMESTAMP.search(fh.read(4096))
        if m:
            stamps.append(m.group(1).decode())
    if stamps:
        out["nvd"] = {"feeds": len(stamps), "oldest_timestamp": min(stamps), "newest_timestamp": max(stamps)}
    cache = d / "derived" / "cve_intel.csv.gz"
    if cache.exists():
        out["intel_cache"] = {"file": cache.name, "sha256": _sha256(cache)}
    manifest = d / "MANIFEST.sha256"
    if manifest.exists():
        out["manifest_sha256"] = _sha256(manifest)
    return out
