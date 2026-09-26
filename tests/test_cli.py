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
