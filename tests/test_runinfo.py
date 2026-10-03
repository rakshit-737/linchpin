from linchpin.runinfo import run_provenance


def test_run_provenance_outside_ci(monkeypatch):
    monkeypatch.delenv("GITHUB_RUN_ID", raising=False)
    p = run_provenance()
    assert set(p) == {"git_commit", "git_dirty_code"}
    assert p["git_commit"] is None or len(p["git_commit"]) == 40  # None in an unpacked sdist


def test_run_provenance_records_the_ci_run(monkeypatch):
    monkeypatch.setenv("GITHUB_RUN_ID", "123")
    monkeypatch.setenv("GITHUB_SHA", "abc")
    monkeypatch.setenv("GITHUB_REPOSITORY", "o/r")
    p = run_provenance()
    assert p["github_run_id"] == "123" and p["github_sha"] == "abc"
    assert p["github_run_url"] == "https://github.com/o/r/actions/runs/123"


def test_run_provenance_without_git(tmp_path):
    p = run_provenance(tmp_path)
    assert p["git_commit"] is None and p["git_dirty_code"] is None
