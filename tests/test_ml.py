import pytest

pytest.importorskip("sklearn")

from linchpin.intel.store import CveRecord
from linchpin.ml.exploitability import ExploitModel, evaluate, train


def _recs():
    out = []
    for i in range(60):
        kev = i % 6 == 0
        out.append(CveRecord(
            cve=f"CVE-2020-{1000 + i}", cvss_base=9.8 if kev else 5.3, epss=0.5 if kev else 0.01, kev=kev,
            cvss_exploitability=1.0 if kev else 0.4, published="2020-01-01", cwe="CWE-78" if kev else "CWE-79",
            cvss_vector=("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" if kev
                         else "CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N"),
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


def test_exploitation_status_is_masked_and_labels_respect_the_cutoff():
    from linchpin.ml.exploitability import features, known_exploited, mask_exploitation_status, mentions_exploitation
    text = ("Use after free in WebKit. Apple is aware of a report that this issue may have been actively "
            "exploited. Exploitation of this issue does not require user interaction.")
    masked = mask_exploitation_status(text)
    assert "aware of a report" not in masked and "does not require user interaction" in masked
    assert mentions_exploitation(text) and not mentions_exploitation(masked)
    assert mentions_exploitation("Google is aware that an exploit for CVE-2024-1 exists in the wild.")
    assert not mentions_exploitation("An attacker could exploit this vulnerability by sending a crafted request.")
    rec = CveRecord(cve="CVE-2021-1", kev=True, kev_date="2023-03-01", description=text)
    assert known_exploited(rec) and not known_exploited(rec, "2023-01-01") and known_exploited(rec, "2023-06-01")
    assert "aware" not in features(rec) and "aware" in features(rec, mask=False)


def test_model_remembers_masking(tmp_path):
    recs = _recs()
    m = train(recs, mask=False)
    p = tmp_path / "m.npz"
    m.save(p)
    assert ExploitModel.load(p).mask is False
    assert train(recs).mask is True
