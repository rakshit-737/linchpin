"""Reproduction: EPSS vs CVSS remediation strategies (Jacobs et al., 2023) with public labels.

Paper: J. Jacobs, S. Romanosky, O. Suciu, B. Edwards, A. Sarabi, "Enhancing Vulnerability
Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights", IEEE European
Symposium on Security and Privacy Workshops (EuroS&PW) 2023, pp. 194-206,
doi:10.1109/EuroSPW59978.2023.00027 (presented at WEIS 2023; arXiv:2302.14172).

For each strategy (flag every CVE whose score is at or above a threshold) we report
**coverage** (share of exploited CVEs flagged = recall), **efficiency** (share of flagged
CVEs that are exploited = precision) and **effort** (share of the population flagged), as in
the paper's Figures 3-5, plus the effort ratio behind its headline ("EPSS reaches CVSS 7+
coverage at one-eighth of the effort": 7.3 / 58.1 = 0.126).

What we can and cannot reproduce:

* The paper's label is proprietary exploitation telemetry (Fortinet, AlienVault, Shadowserver,
  GreyNoise) in the 30 days after 2022-12-01, about 8,000 exploited CVEs. The only public
  label is CISA KEV, a small, curated subset, so coverage and efficiency are not expected to
  match. Two KEV labels are used: ``asof`` (listed in KEV on the scoring date) and
  ``future`` (added to KEV in the 365 days after it, CVEs already listed excluded).
* EPSS takes KEV membership as an input feature (paper Table 1; "Site: KEV" is among its top
  SHAP features, Fig. 7), so EPSS scored against the ``asof`` KEV label is partly circular and
  optimistic. The ``future`` label avoids that but has few positives.
* The paper estimated CVSS v3 vectors for CVEs that only have v2 with its own neural model;
  we cannot, so the CVSS population is the CVEs with an NVD v3.x score.

Setups: ``paper_like`` (primary) -- CVEs published by 2022-12-01 with a CVSS v3.x score and the
EPSS v2 scores *published on 2022-12-01* (FIRST archive, model v2022.01.01, see
scripts/download_data.py); ``current`` (secondary, the v1 analysis) -- every EPSS-scored CVE
to date, today's EPSS and KEV, any CVSS version. Thresholds matched to a coverage or effort are
fixed on the full sample; the 95% intervals are a class-stratified bootstrap (200 replicates)
of the metrics at those thresholds.

    python benchmarks/repro_epss.py --data-dir ../../datasets/linchpin

Writes benchmarks/results/repro_epss.{json,md}.
"""
from __future__ import annotations

import argparse
import csv
import datetime as dt
import gzip
import hashlib
import json
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from linchpin.engine.edge_cost import EdgeContext, exploitability
from linchpin.intel.provenance import feed_provenance

AS_OF = "2022-12-01"
HORIZON_DAYS = 365
# Paper cells, transcribed from arXiv:2302.14172v2 Figures 3-5 (pp. 7-9); percentages.
PAPER = {
    "kev_list":   {"fig": "3", "threshold": "Site:KEV", "effort": 0.5, "coverage": 5.9, "efficiency": 53.2},
    "cvss>=9.1":  {"fig": "4", "threshold": "9.1+", "effort": 15.1, "coverage": 33.5, "efficiency": 6.1},
    "epss_v1_eq_effort": {"fig": "4", "threshold": "0.062+", "effort": 15.1, "coverage": 57.0, "efficiency": 15.4},
    "epss_v2_eq_effort": {"fig": "4", "threshold": "0.037+", "effort": 15.4, "coverage": 69.9, "efficiency": 18.5},
    "epss_v3_eq_effort": {"fig": "4", "threshold": "0.022+", "effort": 15.3, "coverage": 90.4, "efficiency": 24.1},
    "cvss>=7":    {"fig": "5", "threshold": "7+", "effort": 58.1, "coverage": 82.1, "efficiency": 3.9},
    "epss_v1_eq_cov": {"fig": "5", "threshold": "0.015+", "effort": 44.3, "coverage": 82.2, "efficiency": 7.6},
    "epss_v2_eq_cov": {"fig": "5", "threshold": "0.012+", "effort": 39.0, "coverage": 84.7, "efficiency": 8.9},
    "epss_v3_eq_cov": {"fig": "5", "threshold": "0.088+", "effort": 7.3, "coverage": 82.0, "efficiency": 45.5},
}
PAPER_RATIO = round(PAPER["epss_v3_eq_cov"]["effort"] / PAPER["cvss>=7"]["effort"], 3)  # 0.126, "one-eighth"


def _f(x):
    return None if x in (None, "") else float(x)


def _sha(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _epss_file(p: Path) -> tuple[dict[str, float], dict]:
    with gzip.open(p, "rt", encoding="utf-8") as fh:
        head = fh.readline().strip()
        meta = dict(kv.split(":", 1) for kv in head.lstrip("#").split(",") if ":" in kv)
        scores = {r["cve"]: float(r["epss"]) for r in csv.DictReader(fh)}
    return scores, {"model_version": meta.get("model_version"), "score_date": meta.get("score_date"),
                    "file": p.name, "sha256": _sha(p), "rows": len(scores)}


def load(intel_path: Path, hist: dict[str, float]):
    """One dict per CVE from the intel cache (+ historical EPSS where present)."""
    with gzip.open(intel_path, "rt", encoding="utf-8", newline="") as fh:
        first = fh.readline()
        reader = (csv.DictReader(fh) if first.startswith("#")
                  else csv.DictReader(fh, fieldnames=next(csv.reader([first]))))
        for r in reader:
            base, expl, epss = _f(r.get("cvss_base")), _f(r.get("cvss_exploitability")), _f(r.get("epss"))
            yield {"cve": r["cve"], "published": r.get("published") or "",
                   "v3": (r.get("cvss_version") or "")[:1] == "3", "base": base, "epss": epss,
                   "epss_hist": hist.get(r["cve"]),
                   "kev": str(r.get("kev")).lower() in ("true", "1"), "kev_date": r.get("kev_date") or "",
                   # LINCHPIN's exploitability blend without the KEV floor (scoring KEV against itself)
                   "ours": exploitability(EdgeContext(rel="ENABLES", cvss_base=base, cvss_exploitability=expl,
                                                      epss=epss, kev=False)) if epss is not None else None}


class Pop:
    """A population with a 0/1 label and score columns, plus metric helpers."""

    def __init__(self, rows: list[dict], label: str, scores: dict[str, str]):
        self.y = np.array([r[label] for r in rows], dtype=bool)
        self.s = {k: np.array([np.nan if r[col] is None else r[col] for r in rows], dtype=float)
                  for k, col in scores.items()}
        self.n = len(rows)

    def metrics(self, flag: np.ndarray, idx: np.ndarray | None = None) -> dict:
        y = self.y if idx is None else self.y[idx]
        f = flag if idx is None else flag[idx]
        tp, nf, pos = int((f & y).sum()), int(f.sum()), int(y.sum())
        return {"effort": 100 * nf / len(y), "coverage": 100 * tp / pos if pos else float("nan"),
                "efficiency": 100 * tp / nf if nf else float("nan"), "flagged": nf, "tp": tp}

    def at(self, key: str, t: float) -> np.ndarray:
        v = self.s[key]
        return np.nan_to_num(v, nan=-1.0) >= t

    def thr_for_coverage(self, key: str, cov: float) -> float:
        vals = np.sort(np.nan_to_num(self.s[key][self.y], nan=-1.0))[::-1]
        need = max(1, int(np.ceil(len(vals) * cov / 100)))
        return float(vals[min(need, len(vals)) - 1])

    def thr_for_effort(self, key: str, effort: float) -> float:
        vals = np.sort(np.nan_to_num(self.s[key], nan=-1.0))[::-1]
        k = max(1, round(self.n * effort / 100))
        return float(vals[min(k, len(vals)) - 1])

    def boot(self, flag: np.ndarray, reps: int = 200, seed: int = 0) -> dict:
        rng = np.random.default_rng(seed)
        pos, neg = np.flatnonzero(self.y), np.flatnonzero(~self.y)
        out = {"effort": [], "coverage": [], "efficiency": []}
        for _ in range(reps):
            idx = np.concatenate([rng.choice(pos, len(pos)), rng.choice(neg, len(neg))])
            m = self.metrics(flag, idx)
            for k in out:
                out[k].append(m[k])
        return {k + "_ci95": [round(float(x), 3) for x in np.nanpercentile(v, [2.5, 97.5])] for k, v in out.items()}


def evaluate(pop: Pop, epss_key: str, boot: int) -> dict:
    """The paper's comparisons on one population: equal coverage (CVSS 7+) and equal effort (CVSS 9.1+)."""
    res: dict = {"n": pop.n, "positives": int(pop.y.sum()), "base_rate_pct": round(100 * pop.y.mean(), 4)}

    def row(name: str, flag: np.ndarray, threshold) -> dict:
        m = {k: (round(v, 3) if isinstance(v, float) else v) for k, v in pop.metrics(flag).items()}
        return {"name": name, "threshold": threshold, **m, **(pop.boot(flag, boot) if boot else {})}

    c7 = row("cvss>=7", pop.at("cvss", 7.0), 7.0)
    c91 = row("cvss>=9.1", pop.at("cvss", 9.1), 9.1)
    te = pop.thr_for_coverage(epss_key, c7["coverage"])
    e_cov = row("epss_eq_cov", pop.at(epss_key, te), round(te, 4))
    tf = pop.thr_for_effort(epss_key, c91["effort"])
    e_eff = row("epss_eq_effort", pop.at(epss_key, tf), round(tf, 4))
    to = pop.thr_for_coverage("ours", c7["coverage"])
    o_cov = row("ours_eq_cov", pop.at("ours", to), round(to, 4))
    res["rows"] = [c7, e_cov, o_cov, c91, e_eff]
    # Matching CVSS 7+'s coverage is impossible without flagging (almost) everything when too many
    # exploited CVEs share the most common (near-minimum) EPSS value: report that, not a ratio.
    vals = pop.s[epss_key]
    res["epss_needed_for_equal_coverage"] = te
    res["positives_at_or_below_needed"] = int((pop.y & (vals <= te)).sum())
    res["population_share_at_needed_value"] = round(float(np.mean(vals == te)), 4)
    res["equal_coverage_reachable"] = e_cov["effort"] < 99.0
    res["effort_ratio_epss_vs_cvss7"] = (round(e_cov["effort"] / c7["effort"], 3)
                                         if c7["effort"] and res["equal_coverage_reachable"] else None)
    res["coverage_gain_at_cvss91_effort"] = round(e_eff["coverage"] - c91["coverage"], 2)
    return res


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data-dir", default="../../datasets/linchpin")
    ap.add_argument("--out", default="benchmarks/results")
    ap.add_argument("--boot", type=int, default=200)
    a = ap.parse_args(argv)
    d = Path(a.data_dir)
    intel = d / "derived" / "cve_intel.csv.gz"
    hist_path = d / "epss" / "history" / f"epss_scores-{AS_OF}.csv.gz"
    for p in (intel, hist_path):
        if not p.exists():
            print(f"missing {p} (run scripts/download_data.py and linchpin intel-build)", file=sys.stderr)
            return 2
    hist, hist_meta = _epss_file(hist_path)
    cur_epss = next((d / "epss").glob("epss_scores-*.csv*"))
    _, cur_meta = _epss_file(cur_epss)
    kev_doc = json.loads((d / "kev" / "known_exploited_vulnerabilities.json").read_text(encoding="utf-8"))
    rows = list(load(intel, hist))
    end = (dt.date.fromisoformat(AS_OF) + dt.timedelta(days=HORIZON_DAYS)).isoformat()
    for r in rows:
        r["label_asof"] = r["kev"] and bool(r["kev_date"]) and r["kev_date"] <= AS_OF
        r["label_future"] = r["kev"] and AS_OF < r["kev_date"] <= end
        r["label_now"] = r["kev"]
    paper = [r for r in rows if r["published"] and r["published"] <= AS_OF and r["v3"] and r["base"] is not None
             and r["epss_hist"] is not None]
    paper_future = [r for r in paper if not r["label_asof"]]  # prospective: already-listed CVEs excluded
    current = [r for r in rows if r["epss"] is not None]
    scores_hist = {"cvss": "base", "epss": "epss_hist", "ours": "ours"}
    scores_cur = {"cvss": "base", "epss": "epss", "ours": "ours"}
    results = {
        "paper_like_asof": evaluate(Pop(paper, "label_asof", scores_hist), "epss", a.boot),
        "paper_like_future": evaluate(Pop(paper_future, "label_future", scores_hist), "epss", a.boot),
        "current": evaluate(Pop(current, "label_now", scores_cur), "epss", a.boot),
    }
    out = {
        "paper": PAPER, "paper_effort_ratio": PAPER_RATIO,
        "setups": {
            "paper_like_asof": f"published <= {AS_OF}, NVD CVSS v3.x, EPSS {hist_meta['model_version']} scores of "
                               f"{AS_OF}; label = in KEV on {AS_OF} (EPSS ingests KEV: circular, optimistic)",
            "paper_like_future": f"same population minus CVEs already in KEV; label = added to KEV in "
                                 f"({AS_OF}, {end}] (prospective, few positives)",
            "current": f"every EPSS-scored CVE, EPSS {cur_meta['model_version']} of {cur_meta['score_date'][:10]}, "
                       "CVSS any version; label = in today's KEV (the v1 analysis)"},
        "results": results,
        "provenance": {"epss_history": hist_meta, "epss_current": cur_meta,
                       "kev": {"catalogVersion": kev_doc.get("catalogVersion"),
                               "dateReleased": kev_doc.get("dateReleased"), "count": kev_doc.get("count")},
                       "intel_cache": {"file": intel.name, "sha256": _sha(intel)},
                       "feeds": feed_provenance(d)},
    }
    dd = Path(a.out)
    dd.mkdir(parents=True, exist_ok=True)
    (dd / "repro_epss.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
    text = render(out)
    (dd / "repro_epss.md").write_text(text, encoding="utf-8")
    print(text)
    return 0


def _cell(r: dict, k: str) -> str:
    v = r.get(k)
    if v is None or v != v:
        return "n/r"
    ci = r.get(k + "_ci95")
    return f"{v:.1f}" + (f" [{ci[0]:.1f}, {ci[1]:.1f}]" if ci else "")


def render(out: dict) -> str:
    P = out["paper"]
    lines = [
        "Reproduction of Jacobs et al., *Enhancing Vulnerability Prioritization* (IEEE EuroS&PW 2023 / WEIS 2023, "
        "arXiv:2302.14172), Figures 3-5. Effort = % of the population flagged; coverage = % of exploited CVEs "
        "flagged (recall); efficiency = % of flagged CVEs exploited (precision). Brackets: 95% class-stratified "
        "bootstrap interval at the fixed threshold. n/r = not reported by the paper.", ""]
    for key, title in (("paper_like_asof", "Primary: paper-like population, KEV on the scoring date as the label"),
                       ("paper_like_future", "Prospective: KEV additions in the following year as the label"),
                       ("current", "Secondary: every CVE to date (the v1 analysis)")):
        r = out["results"][key]
        lines += [f"### {title}", "", f"{out['setups'][key]}. n = {r['n']:,}, exploited = {r['positives']:,} "
                  f"(base rate {r['base_rate_pct']:.3f}%).", "",
                  "| strategy | threshold | effort % | coverage % | efficiency % | paper (effort / coverage / "
                  "efficiency) |", "| --- | ---: | ---: | ---: | ---: | --- |"]
        paper_for = {"cvss>=7": "cvss>=7", "epss_eq_cov": "epss_v2_eq_cov" if "paper_like" in key else "epss_v3_eq_cov",
                     "cvss>=9.1": "cvss>=9.1", "epss_eq_effort": "epss_v2_eq_effort" if "paper_like" in key
                     else "epss_v3_eq_effort", "ours_eq_cov": None}
        names = {"cvss>=7": "CVSS 7+", "epss_eq_cov": "EPSS, coverage matched to CVSS 7+",
                 "ours_eq_cov": "LINCHPIN blend (no KEV floor), coverage matched", "cvss>=9.1": "CVSS 9.1+",
                 "epss_eq_effort": "EPSS, effort matched to CVSS 9.1+"}
        for row in r["rows"]:
            pk = paper_for[row["name"]]
            p = P.get(pk) if pk else None
            ver = "EPSS v2 " if pk and "v2" in pk else "EPSS v3 " if pk and "v3" in pk else ""
            ptxt = ("n/r" if not p else
                    f"{p['effort']} / {p['coverage']} / {p['efficiency']} (Fig. {p['fig']}, {ver}{p['threshold']})")
            if row["name"] == "epss_eq_cov" and not r["equal_coverage_reachable"]:
                lines.append(f"| {names[row['name']]} | {row['threshold']} | n/a (ties) | n/a (ties) | n/a (ties) "
                             f"| {ptxt} |")
                continue
            lines.append(f"| {names[row['name']]} | {row['threshold']} | {_cell(row, 'effort')} | "
                         f"{_cell(row, 'coverage')} | {_cell(row, 'efficiency')} | {ptxt} |")
        ratio = (f"**{r['effort_ratio_epss_vs_cvss7']}**" if r["equal_coverage_reachable"] else
                 f"not reachable ({r['positives_at_or_below_needed']} of the {r['positives']} exploited CVEs scored "
                 f"at most {r['epss_needed_for_equal_coverage']:.5f}, the most common EPSS value, held by "
                 f"{r['population_share_at_needed_value']:.0%} of the population; matching CVSS 7+'s coverage "
                 "therefore flags almost every CVE)")
        lines += ["", f"Effort ratio EPSS / CVSS 7+ at equal coverage: {ratio} "
                      f"(paper, EPSS v3: {out['paper_effort_ratio']}, \"one-eighth\"; paper, EPSS v2: "
                      f"{round(P['epss_v2_eq_cov']['effort'] / P['cvss>=7']['effort'], 3)}). Coverage gain of EPSS "
                      f"over CVSS 9.1+ at equal effort: {r['coverage_gain_at_cvss91_effort']:+.1f} points (paper: "
                      f"{P['epss_v2_eq_effort']['coverage'] - P['cvss>=9.1']['coverage']:+.1f} with v2, "
                      f"{P['epss_v3_eq_effort']['coverage'] - P['cvss>=9.1']['coverage']:+.1f} with v3).", ""]
    k = P["kev_list"]
    pv = out["provenance"]
    lines += [f"The paper's KEV-list strategy (Fig. 3: effort {k['effort']}%, coverage {k['coverage']}%, efficiency "
              f"{k['efficiency']}%) has no counterpart here: with KEV as the label it would be tautological.", "",
              "Provenance: EPSS history " + f"{pv['epss_history']['model_version']} / "
              f"{pv['epss_history']['score_date']} (sha256 {pv['epss_history']['sha256'][:16]}...), EPSS current "
              f"{pv['epss_current']['model_version']} / {pv['epss_current']['score_date']}, KEV catalog "
              f"{pv['kev']['catalogVersion']} ({pv['kev']['dateReleased']}), intel cache sha256 "
              f"{pv['intel_cache']['sha256'][:16]}...", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
