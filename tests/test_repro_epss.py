"""The EPSS reproduction's paper cells and statistics (no datasets needed)."""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

np = pytest.importorskip("numpy")


def _mod():
    path = Path(__file__).parents[1] / "benchmarks" / "repro_epss.py"
    spec = importlib.util.spec_from_file_location("repro_epss", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Jacobs et al., arXiv:2302.14172v2, as read from the PDF on 2026-10-03
# (benchmarks/results/repro_epss_paper_check.md): (figure, threshold, effort, coverage, efficiency).
PDF_CELLS = {
    "kev_list": ("3", "Site:KEV", 0.5, 5.9, 53.2),
    "cvss>=9.1": ("4", "9.1+", 15.1, 33.5, 6.1),
    "epss_v1_eq_effort": ("4", "0.062+", 15.1, 57.0, 15.4),
    "epss_v2_eq_effort": ("4", "0.037+", 15.4, 69.9, 18.5),
    "epss_v3_eq_effort": ("4", "0.022+", 15.3, 90.4, 24.1),
    "cvss>=7": ("5", "7+", 58.1, 82.1, 3.9),
    "epss_v1_eq_cov": ("5", "0.015+", 44.3, 82.2, 7.6),
    "epss_v2_eq_cov": ("5", "0.012+", 39.0, 84.7, 8.9),
    "epss_v3_eq_cov": ("5", "0.088+", 7.3, 82.0, 45.5),
}


def test_paper_cells_match_the_checked_pdf_values():
    paper = _mod().PAPER
    assert set(paper) == set(PDF_CELLS)
    for key, (fig, thr, effort, cov, eff) in PDF_CELLS.items():
        p = paper[key]
        assert (p["fig"], p["threshold"], p["effort"], p["coverage"], p["efficiency"]) == (fig, thr, effort, cov, eff)


def test_paper_effort_ratios():
    m = _mod()
    assert m.PAPER_RATIO == 0.126  # EPSS v3, "one-eighth"
    assert m.PAPER_RATIO_V2 == 0.671


def _pop(m, y, a, b):
    rows = [{"y": bool(t), "a": float(x), "b": float(z)} for t, x, z in zip(y, a, b, strict=True)]
    return m.Pop(rows, "y", {"cvss": "a", "epss": "b"})


def test_paired_coverage_counts_and_exact_mcnemar():
    m = _mod()
    # 10 positives: both flag 2, only a flags 6, only b flags 1, neither 1; 5 negatives
    a = [1, 1, 1, 1, 1, 1, 1, 1, 0, 0] + [0] * 5
    b = [1, 1, 0, 0, 0, 0, 0, 0, 1, 0] + [0] * 5
    y = [1] * 10 + [0] * 5
    pop = _pop(m, y, a, b)
    fa, fb = np.array(a, dtype=bool), np.array(b, dtype=bool)
    pc = m.paired_coverage(pop, fa, fb, reps=2000, seed=0)
    assert (pc["both"], pc["only_a"], pc["only_b"], pc["neither"]) == (2, 6, 1, 1)
    assert pc["p_mcnemar_exact"] == pytest.approx(2 * (1 + 7) / 2 ** 7)  # 0.125
    assert pc["coverage_diff_points"] == pytest.approx(50.0)
    lo, hi = pc["coverage_diff_ci95"]
    assert lo < 50.0 < hi


def test_metrics_carry_wilson_intervals():
    m = _mod()
    y = [1] * 4 + [0] * 16
    a = [1, 1, 0, 0] + [1] * 2 + [0] * 14
    pop = _pop(m, y, a, a)
    met = pop.metrics(np.array(a, dtype=bool))
    assert met["effort"] == pytest.approx(20.0) and met["coverage"] == pytest.approx(50.0)
    assert met["efficiency"] == pytest.approx(50.0)
    lo, hi = met["coverage_ci95"]
    assert lo == pytest.approx(15.0, abs=0.1) and hi == pytest.approx(85.0, abs=0.1)  # Wilson 2/4
