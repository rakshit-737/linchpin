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
* EPSS v3 takes KEV membership as an input feature (paper Table 1; "Site: KEV" is among its top
  SHAP features, Fig. 7). The paper does not list the v2 features (only that there were 1,164),
  so for the v2 scores used here this is likely but not documented; if it holds, EPSS scored
  against the ``asof`` KEV label is partly circular and optimistic. The ``future`` label avoids
  that but has few positives.
* The paper estimated CVSS v3 vectors for CVEs that only have v2 with its own neural model;
  we cannot, so the CVSS population is the CVEs with an NVD v3.x score.

Setups: ``paper_like`` (primary) -- CVEs published by 2022-12-01 with a CVSS v3.x score and the
EPSS v2 scores *published on 2022-12-01* (FIRST archive, model v2022.01.01, see
scripts/download_data.py); ``current`` (secondary, the v1 analysis) -- every EPSS-scored CVE
to date, today's EPSS and KEV, any CVSS version. Thresholds matched to a coverage or effort are
fixed on the full sample. At a fixed threshold effort, coverage and efficiency are proportions
k/n, so they carry 95% Wilson intervals. The effort ratio at equal coverage gets a
class-stratified bootstrap interval (1,000 replicates, EPSS threshold re-matched to CVSS 7+'s
coverage in every replicate). EPSS and CVSS 9.1+ at equal effort are compared *paired*, on the
same exploited CVEs: discordant counts, exact two-sided McNemar test, and a paired bootstrap
(10,000 replicates over the exploited CVEs) of the coverage difference.

The paper cells in :data:`PAPER` were checked against the arXiv v2 PDF on 2026-10-03; the record
is benchmarks/results/repro_epss_paper_check.md.

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

from linchpin.benchmark import format_p, mcnemar_exact, wilson_ci
from linchpin.engine.edge_cost import EdgeContext, exploitability
from linchpin.intel.provenance import feed_provenance
from linchpin.runinfo import run_provenance

AS_OF = "2022-12-01"
HORIZON_DAYS = 365
# Paper cells, transcribed from arXiv:2302.14172v2 Figures 3-5 (pp. 7-9); percentages. Checked cell by cell
# against the PDF (benchmarks/results/repro_epss_paper_check.md); tests/test_repro_epss.py pins them.
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
PAPER_RATIO_V2 = round(PAPER["epss_v2_eq_cov"]["effort"] / PAPER["cvss>=7"]["effort"], 3)  # 0.671


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

    def metrics(self, flag: np.ndarray) -> dict:
        """Effort, coverage and efficiency (%) of ``flag``, each with a 95% Wilson interval (k/n proportions)."""
        y, f = self.y, flag
        tp, nf, pos = int((f & y).sum()), int(f.sum()), int(y.sum())
        out: dict = {"flagged": nf, "tp": tp}
        for name, k, n in (("effort", nf, len(y)), ("coverage", tp, pos), ("efficiency", tp, nf)):
            out[name] = 100 * k / n if n else float("nan")
            out[name + "_ci95"] = [100 * x for x in wilson_ci(k, n, ndigits=None)] if n else None
        return out

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

    def effort_ratio_boot(self, key: str, reps: int = 1000, seed: int = 0) -> dict:
        """Class-stratified bootstrap of EPSS / CVSS 7+ effort at CVSS 7+'s coverage, threshold re-matched."""
        rng = np.random.default_rng(seed)
        pos, neg = np.flatnonzero(self.y), np.flatnonzero(~self.y)
        cvss = np.nan_to_num(self.s["cvss"], nan=-1.0)
        score = np.nan_to_num(self.s[key], nan=-1.0)
        ratios, unreachable = [], 0
        for _ in range(reps):
            ip, ineg = rng.choice(pos, len(pos)), rng.choice(neg, len(neg))
            c7_pos = cvss[ip] >= 7.0
            n = len(ip) + len(ineg)
            effort_cvss = (c7_pos.sum() + (cvss[ineg] >= 7.0).sum()) / n
            vals = np.sort(score[ip])[::-1]
            need = max(1, int(np.ceil(round(len(vals) * c7_pos.mean(), 9))))
            t = vals[min(need, len(vals)) - 1]
            effort_epss = ((score[ip] >= t).sum() + (score[ineg] >= t).sum()) / n
            if effort_epss >= 0.99:  # ties at the floor: equal coverage not reachable in this replicate
                unreachable += 1
                continue
            ratios.append(effort_epss / effort_cvss)
        ci = [round(float(x), 4) for x in np.percentile(ratios, [2.5, 97.5])] if ratios else None
        return {"ci95": ci, "reps": reps, "unreachable_reps": unreachable, "seed": seed,
                "method": "class-stratified bootstrap, EPSS threshold re-matched to CVSS 7+'s coverage per replicate"}


def paired_coverage(pop: Pop, a: np.ndarray, b: np.ndarray, reps: int = 10_000, seed: int = 0) -> dict:
    """Flags ``a`` and ``b`` on the same exploited CVEs: discordant counts, exact McNemar, paired bootstrap."""
    fa, fb = a[pop.y], b[pop.y]
    only_a, only_b = int((fa & ~fb).sum()), int((~fa & fb).sum())
    d = fa.astype(np.int8) - fb.astype(np.int8)
    rng = np.random.default_rng(seed)
    boots = np.concatenate([d[rng.integers(0, len(d), size=(min(1000, reps - i), len(d)))].mean(axis=1)
                            for i in range(0, reps, 1000)])
    lo, hi = np.percentile(boots, [2.5, 97.5])
    return {"positives": len(d), "both": int((fa & fb).sum()), "only_a": only_a, "only_b": only_b,
            "neither": int((~fa & ~fb).sum()), "p_mcnemar_exact": mcnemar_exact(only_a, only_b),
            "coverage_diff_points": round(100 * float(d.mean()), 3),
            "coverage_diff_ci95": [round(100 * float(lo), 3), round(100 * float(hi), 3)],
            "bootstrap": {"reps": reps, "seed": seed, "resampled": "exploited CVEs (paired)"}}


def evaluate(pop: Pop, epss_key: str, ratio_reps: int, paired_reps: int) -> dict:
    """The paper's comparisons on one population: equal coverage (CVSS 7+) and equal effort (CVSS 9.1+)."""
    res: dict = {"n": pop.n, "positives": int(pop.y.sum()), "base_rate_pct": round(100 * pop.y.mean(), 4)}

    def row(name: str, flag: np.ndarray, threshold) -> dict:
        return {"name": name, "threshold": threshold, **pop.metrics(flag)}

    f7, f91 = pop.at("cvss", 7.0), pop.at("cvss", 9.1)
    c7 = row("cvss>=7", f7, 7.0)
    c91 = row("cvss>=9.1", f91, 9.1)
    # thresholds are matched to the 3-decimal coverage / effort, as in the published v1.1.0 tables
    te = pop.thr_for_coverage(epss_key, round(c7["coverage"], 3))
    e_cov = row("epss_eq_cov", pop.at(epss_key, te), round(te, 4))
    tf = pop.thr_for_effort(epss_key, round(c91["effort"], 3))
    f_eff = pop.at(epss_key, tf)
    e_eff = row("epss_eq_effort", f_eff, round(tf, 4))
    to = pop.thr_for_coverage("ours", round(c7["coverage"], 3))
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
    res["effort_ratio_ci95"] = (pop.effort_ratio_boot(epss_key, ratio_reps)
                                if res["equal_coverage_reachable"] and ratio_reps else None)
    res["coverage_gain_at_cvss91_effort"] = round(e_eff["coverage"] - c91["coverage"], 2)
    # a = EPSS at CVSS 9.1+'s effort, b = CVSS 9.1+, compared on the same exploited CVEs
    res["paired_epss_vs_cvss91"] = paired_coverage(pop, f_eff, f91, paired_reps)
    return res


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data-dir", default="../../datasets/linchpin")
    ap.add_argument("--out", default="benchmarks/results")
    ap.add_argument("--ratio-boot", type=int, default=1000, help="bootstrap replicates for the effort ratio")
    ap.add_argument("--paired-boot", type=int, default=10_000, help="paired bootstrap replicates (coverage gap)")
    ap.add_argument("--render-only", action="store_true", help="only rewrite repro_epss.md from repro_epss.json")
    a = ap.parse_args(argv)
    if a.render_only:
        doc = json.loads((Path(a.out) / "repro_epss.json").read_text(encoding="utf-8"))
        (Path(a.out) / "repro_epss.md").write_text(render(doc), encoding="utf-8")
        return 0
    code = run_provenance()
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
        "paper_like_asof": evaluate(Pop(paper, "label_asof", scores_hist), "epss", a.ratio_boot, a.paired_boot),
        "paper_like_future": evaluate(Pop(paper_future, "label_future", scores_hist), "epss", a.ratio_boot,
                                      a.paired_boot),
        "current": evaluate(Pop(current, "label_now", scores_cur), "epss", a.ratio_boot, a.paired_boot),
    }
    out = {
        "paper": PAPER, "paper_effort_ratio": PAPER_RATIO, "paper_effort_ratio_v2": PAPER_RATIO_V2,
        "paper_check": "benchmarks/results/repro_epss_paper_check.md",
        "setups": {
            "paper_like_asof": f"published <= {AS_OF}, NVD CVSS v3.x, EPSS {hist_meta['model_version']} scores of "
                               f"{AS_OF}; label = in KEV on {AS_OF} (EPSS ingests KEV: circular, optimistic)",
            "paper_like_future": f"same population minus CVEs already in KEV; label = added to KEV in "
                                 f"({AS_OF}, {end}] (prospective, few positives)",
            "current": f"every EPSS-scored CVE, EPSS {cur_meta['model_version']} of {cur_meta['score_date'][:10]}, "
                       "CVSS any version; label = in today's KEV (the v1 analysis)"},
        "results": results,
        "provenance": {"code": code, "epss_history": hist_meta, "epss_current": cur_meta,
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


def _cell(r: dict, k: str, digits: int = 1) -> str:
    v = r.get(k)
    if v is None or v != v:
        return "n/r"
    ci = r.get(k + "_ci95")
    return f"{v:.{digits}f}" + (f" [{ci[0]:.{digits}f}, {ci[1]:.{digits}f}]" if ci else "")


def _p_eq(p: float) -> str:
    txt = format_p(p)
    return f"p {txt}" if txt.startswith("<") else f"p = {txt}"


def paired_sentence(r: dict) -> str:
    """One line: EPSS at CVSS 9.1+'s effort against CVSS 9.1+, paired on the same exploited CVEs."""
    pc = r["paired_epss_vs_cvss91"]
    lo, hi = pc["coverage_diff_ci95"]
    return (f"Paired on the same {pc['positives']:,} exploited CVEs, EPSS at CVSS 9.1+'s effort flags {pc['only_a']:,} "
            f"that CVSS 9.1+ misses and misses {pc['only_b']:,} that it flags ({pc['both']:,} flagged by both, "
            f"{pc['neither']:,} by neither): exact McNemar {_p_eq(pc['p_mcnemar_exact'])}; coverage difference "
            f"{pc['coverage_diff_points']:+.1f} points, paired bootstrap 95% [{lo:+.1f}, {hi:+.1f}] "
            f"({pc['bootstrap']['reps']:,} replicates over the exploited CVEs, seed {pc['bootstrap']['seed']}).")


def _ratio_text(out: dict, key: str, r: dict) -> str:
    if not r["equal_coverage_reachable"]:
        return (f"not reachable ({r['positives_at_or_below_needed']} of the {r['positives']} exploited CVEs scored "
                f"at most {r['epss_needed_for_equal_coverage']:.5f}, the most common EPSS value, held by "
                f"{r['population_share_at_needed_value']:.0%} of the population; matching CVSS 7+'s coverage "
                "therefore flags almost every CVE)")
    txt = f"**{r['effort_ratio_epss_vs_cvss7']:.3f}**"
    rb = r.get("effort_ratio_ci95") or {}
    ci = rb.get("ci95")
    if ci:
        txt += (f" [{ci[0]:.3f}, {ci[1]:.3f}] ({rb['method']}, {rb['reps']:,} replicates, seed {rb['seed']}"
                + (f"; {rb['unreachable_reps']} replicates could not match the coverage" if rb["unreachable_reps"]
                   else "") + ")")
        if key.startswith("paper_like"):
            v2 = out["paper_effort_ratio_v2"]
            txt += f"; the paper's EPSS v2 ratio {v2} lies {'inside' if ci[0] <= v2 <= ci[1] else 'outside'} it"
    return txt


def render(out: dict) -> str:
    P = out["paper"]
    lines = [
        "Reproduction of Jacobs et al., *Enhancing Vulnerability Prioritization* (IEEE EuroS&PW 2023 / WEIS 2023, "
        "arXiv:2302.14172), Figures 3-5. Effort = % of the population flagged; coverage = % of exploited CVEs "
        "flagged (recall); efficiency = % of flagged CVEs exploited (precision). Brackets: 95% Wilson interval of "
        "that proportion at the fixed threshold. n/r = not reported by the paper. Every paper cell was checked "
        "against the arXiv v2 PDF (benchmarks/results/repro_epss_paper_check.md).", ""]
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
                         f"{_cell(row, 'coverage')} | {_cell(row, 'efficiency', 2)} | {ptxt} |")
        lines += ["", f"Effort ratio EPSS / CVSS 7+ at equal coverage: {_ratio_text(out, key, r)} (paper, EPSS v3: "
                      f"{out['paper_effort_ratio']}, \"one-eighth\"; paper, EPSS v2: {out['paper_effort_ratio_v2']}, "
                      f"at 84.7% vs 82.1% coverage). Coverage gain of EPSS over CVSS 9.1+ at equal effort: "
                      f"{r['coverage_gain_at_cvss91_effort']:+.1f} points (paper: "
                      f"{P['epss_v2_eq_effort']['coverage'] - P['cvss>=9.1']['coverage']:+.1f} with v2, "
                      f"{P['epss_v3_eq_effort']['coverage'] - P['cvss>=9.1']['coverage']:+.1f} with v3).", "",
                  paired_sentence(r), ""]
    k = P["kev_list"]
    pv = out["provenance"]
    code = pv.get("code") or {}
    lines += [f"The paper's KEV-list strategy (Fig. 3: effort {k['effort']}%, coverage {k['coverage']}%, efficiency "
              f"{k['efficiency']}%) has no counterpart here: with KEV as the label it would be tautological.", "",
              "Provenance: EPSS history " + f"{pv['epss_history']['model_version']} / "
              f"{pv['epss_history']['score_date']} (sha256 {pv['epss_history']['sha256'][:16]}...), EPSS current "
              f"{pv['epss_current']['model_version']} / {pv['epss_current']['score_date']}, KEV catalog "
              f"{pv['kev']['catalogVersion']} ({pv['kev']['dateReleased']}), intel cache sha256 "
              f"{pv['intel_cache']['sha256'][:16]}...; code at commit {(code.get('git_commit') or 'unknown')[:12]}"
              + (" with uncommitted code changes" if code.get("git_dirty_code") else "") + ".", ""]
    return "\n".join(lines)


if __name__ == "__main__":
    raise SystemExit(main())
