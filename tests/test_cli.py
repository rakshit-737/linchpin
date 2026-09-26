import json

from linchpin.cli import main


def run(capsys, *argv):
    rc = main(list(argv))
    return rc, capsys.readouterr().out


def test_cli_flow(tmp_path, capsys):
    st = str(tmp_path / "state.json")
    data = str(tmp_path / "synth.json")
    base = ["--state", st, "--config", str(tmp_path / "none.yaml")]
    rc, out = run(capsys, *base, "synth", "--out", data, "--seed", "3")
    assert rc == 0 and json.loads(out)["ground_truth"]["linchpin"] == "host:jump-01"
    rc, out = run(capsys, *base, "ingest", data)
    assert rc == 0 and json.loads(out)["accepted"] > 0
    rc, out = run(capsys, *base, "build")
    assert rc == 0 and json.loads(out)["nodes"] > 0
    rc, out = run(capsys, *base, "paths", "--k", "3")
    paths = json.loads(out)
    assert rc == 0 and len(paths) == 3 and {"path_id", "nodes", "total_cost"} <= set(paths[0])
    rc, out = run(capsys, *base, "fix", "--budget", "2")
    assert rc == 0 and json.loads(out)[0]["target_node"] == "host:jump-01"
    rc, out = run(capsys, *base, "whatif", "--remove", "jump-01")
    assert rc == 0 and json.loads(out)["paths_after"] == 0
    rc, _ = run(capsys, *base, "node", "does-not-exist")
    assert rc == 2


def test_cli_real_exports_scenario_cuts_export(tmp_path, capsys):
    from pathlib import Path
    fix = Path(__file__).parent / "fixtures"
    st = str(tmp_path / "state.json")
    base = ["--state", st, "--config", str(tmp_path / "none.yaml")]
    rc, out = run(capsys, *base, "ingest", "--replace", str(fix / "openvas_sample.xml"),
                  str(fix / "nessus_sample.nessus"), str(fix / "bloodhound"))
    got = json.loads(out)
    assert rc == 0 and got["accepted"] > 20 and not got["skipped"]
    rc, out = run(capsys, *base, "scenario", str(fix / "scenario_mini.yaml"))
    assert rc == 0 and json.loads(out)["name"] == "mini"
    rc, out = run(capsys, *base, "cuts")
    cuts = json.loads(out)
    assert rc == 0 and "cred:ADMINISTRATOR@TESTLAB.LOCAL" in cuts["chokepoints"]
    rc, out = run(capsys, *base, "fix", "--budget", "1")
    assert rc == 0 and json.loads(out)[0]["residual_paths"] == 0
    for fmt in ("cypher", "graphml"):
        dest = tmp_path / f"g.{fmt}"
        rc, _ = run(capsys, *base, "export", "--format", fmt, "--out", str(dest))
        assert rc == 0 and dest.stat().st_size > 1000
