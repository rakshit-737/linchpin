import pytest

pytest.importorskip("sklearn")

from linchpin.intel.store import CveRecord  # noqa: E402
from linchpin.ml.exploitability import ExploitModel, evaluate, train  # noqa: E402


def _recs():
    out = []
    for i in range(60):
        kev = i % 6 == 0
        out.append(CveRecord(
            cve=f"CVE-2020-{1000 + i}", cvss_base=9.8 if kev else 5.3, epss=0.5 if kev else 0.01, kev=kev,
            cvss_exploitability=1.0 if kev else 0.4, published="2020-01-01", cwe="CWE-78" if kev else "CWE-79",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if kev else "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N",
            description=("remote unauthenticated command injection" if kev else "stored cross-site scripting")))
    return out


def test_train_score_save_load(tmp_path):
    recs = _recs()
    m = train(recs)
    s = m.score_many(recs)
    assert all(0 <= x <= 1 for x in s)
    assert s[0] > s[1]  # kev-like record scores higher
    p = tmp_path / "m.npz"
    m.save(p)
    m2 = ExploitModel.load(p)
    assert abs(m2.score(recs[0]) - m.score(recs[0])) < 1e-4
    ev = evaluate(m, recs)
    assert ev["learned"]["roc_auc"] > 0.9
