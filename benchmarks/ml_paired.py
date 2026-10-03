"""M11: paired comparison of the learned exploit model and the CVSS base score on the same test CVEs.

    python benchmarks/ml_paired.py --data-dir ../../datasets/linchpin

Loads the default model that benchmarks/ml_exploitability.py saved (``derived/exploit_model.npz``,
masked text, labels known at the 2023-01-01 cutoff), rebuilds the test set without exploitation-status
phrases (CVEs published from the cutoff whose description does not report exploitation), checks that
the model reproduces the published ROC-AUC and average precision, and then draws a class-stratified
paired bootstrap (both scorers on the same resampled CVEs) of the AUC difference, the AP difference and
the AP ratio. It does not retrain anything. Writes benchmarks/results/ml_paired.{json,md}.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from linchpin.intel import CveIntel
from linchpin.intel.provenance import feed_provenance
from linchpin.ml.exploitability import ExploitModel, mentions_exploitation, temporal_split
from linchpin.runinfo import run_provenance


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--data-dir", default="../../datasets/linchpin")
    ap.add_argument("--cutoff", default="2023-01-01")
    ap.add_argument("--reps", type=int, default=1000)
    ap.add_argument("--out", default="benchmarks/results")
    ap.add_argument("--render-only", action="store_true", help="only rewrite ml_paired.md from ml_paired.json")
    a = ap.parse_args(argv)
    if a.render_only:
        res = json.loads((Path(a.out) / "ml_paired.json").read_text(encoding="utf-8"))
        (Path(a.out) / "ml_paired.md").write_text(render(res), encoding="utf-8")
        return 0
    from sklearn.metrics import average_precision_score, roc_auc_score
    t0 = time.time()
    code = run_provenance()
    d = Path(a.data_dir)
    model_path = d / "derived" / "exploit_model.npz"
    model = ExploitModel.load(model_path)
    intel = CveIntel.load(d / "derived" / "cve_intel.csv.gz")
    _, te = temporal_split(intel, a.cutoff)
    te = [r for r in te if not mentions_exploitation(r.description)]
    y = np.array([r.kev for r in te], dtype=int)
    s_learned = model.score_many(te)
    s_cvss = np.array([r.cvss_base or 0.0 for r in te])
    point = {name: {"roc_auc": float(roc_auc_score(y, s)), "avg_precision": float(average_precision_score(y, s))}
             for name, s in (("learned", s_learned), ("cvss_base", s_cvss))}
    published = json.loads((Path(a.out) / "ml_exploitability.json").read_text(encoding="utf-8"))
    pub = published["setups"]["masked"]["test_without_phrase_cves"]
    same = all(round(point[n][m], 4) == pub[n][m] for n in point for m in ("roc_auc", "avg_precision"))
    rng = np.random.default_rng(0)
    pos, neg = np.flatnonzero(y == 1), np.flatnonzero(y == 0)
    d_auc, d_ap, r_ap = [], [], []
    for _ in range(a.reps):
        i = np.concatenate([rng.choice(pos, len(pos)), rng.choice(neg, len(neg))])
        auc_l, auc_c = roc_auc_score(y[i], s_learned[i]), roc_auc_score(y[i], s_cvss[i])
        ap_l, ap_c = average_precision_score(y[i], s_learned[i]), average_precision_score(y[i], s_cvss[i])
        d_auc.append(auc_l - auc_c)
        d_ap.append(ap_l - ap_c)
        r_ap.append(ap_l / ap_c)

    def ci(xs: list[float]) -> list[float]:
        return [round(float(x), 4) for x in np.percentile(xs, [2.5, 97.5])]

    res = {
        "test_set": f"CVEs published from {a.cutoff} without an exploitation-status phrase", "n_test": len(te),
        "positives": int(y.sum()), "model": {"file": model_path.name, "cutoff": model.cutoff, "mask": model.mask},
        "point": {n: {k: round(v, 4) for k, v in m.items()} for n, m in point.items()},
        "matches_published_ml_exploitability": same,
        "paired": {"roc_auc_diff": round(point["learned"]["roc_auc"] - point["cvss_base"]["roc_auc"], 4),
                   "roc_auc_diff_ci95": ci(d_auc), "roc_auc_learned_better_share": round(float(np.mean(
                       np.array(d_auc) > 0)), 4),
                   "avg_precision_diff": round(point["learned"]["avg_precision"] - point["cvss_base"]["avg_precision"],
                                               4),
                   "avg_precision_diff_ci95": ci(d_ap),
                   "avg_precision_ratio": round(point["learned"]["avg_precision"] / point["cvss_base"]["avg_precision"],
                                                3),
                   "avg_precision_ratio_ci95": ci(r_ap),
                   "bootstrap": {"reps": a.reps, "seed": 0, "method": "class-stratified, both scorers on the same "
                                 "resampled CVEs"}},
        "runtime_s": round(time.time() - t0, 1), "provenance": {"code": code, "feeds": feed_provenance(d)},
    }
    out = Path(a.out)
    (out / "ml_paired.json").write_text(json.dumps(res, indent=2), encoding="utf-8")
    text = render(res)
    (out / "ml_paired.md").write_text(text, encoding="utf-8")
    print(text)
    return 0 if same else 1


def render(res: dict) -> str:
    point, p = res["point"], res["paired"]
    code = res["provenance"]["code"]
    same = res["matches_published_ml_exploitability"]
    return "\n".join([
        f"Paired comparison on the test CVEs without exploitation-status phrases ({res['n_test']:,} CVEs published "
        f"from {res['model']['cutoff']} whose description does not report exploitation, {res['positives']} in KEV): "
        f"the default learned model ({'reproduces' if same else 'does NOT reproduce'} the published ROC-AUC "
        f"{point['learned']['roc_auc']:.3f} and average precision {point['learned']['avg_precision']:.3f}) against "
        f"the CVSS base score, both scored on the same class-stratified bootstrap resamples "
        f"({p['bootstrap']['reps']:,} replicates, seed {p['bootstrap']['seed']}).", "",
        "| metric | learned | CVSS base | learned - CVSS (95% paired bootstrap) | ratio (95%) |",
        "| --- | ---: | ---: | ---: | ---: |",
        f"| ROC-AUC | {point['learned']['roc_auc']:.3f} | {point['cvss_base']['roc_auc']:.3f} | "
        f"{p['roc_auc_diff']:+.3f} [{p['roc_auc_diff_ci95'][0]:+.3f}, {p['roc_auc_diff_ci95'][1]:+.3f}] | - |",
        f"| average precision | {point['learned']['avg_precision']:.4f} | {point['cvss_base']['avg_precision']:.4f} | "
        f"{p['avg_precision_diff']:+.4f} [{p['avg_precision_diff_ci95'][0]:+.4f}, "
        f"{p['avg_precision_diff_ci95'][1]:+.4f}] | {p['avg_precision_ratio']:.2f}x "
        f"[{p['avg_precision_ratio_ci95'][0]:.2f}, {p['avg_precision_ratio_ci95'][1]:.2f}] |", "",
        f"The learned model has the higher ROC-AUC in {p['roc_auc_learned_better_share']:.1%} of the replicates. "
        f"Computed at commit {(code.get('git_commit') or 'unknown')[:12]}"
        + (" with uncommitted code changes" if code.get("git_dirty_code") else "") + ".", ""])


if __name__ == "__main__":
    raise SystemExit(main())
